package decoder

import (
	"sync"
	"time"
	"fmt"
	"log"
	"bufio"
	"os"
	"os/signal"
	"syscall"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"github.com/mitchellh/go-ps"
	"github.com/cloudflare/ebpf_exporter/config"
)

// kubepod is a decoder that transforms pid to podinfo
type KubePod struct {
	workerMu		sync.Mutex
	cacheWorkerRunning	bool
	cacheWorker		CacheWorker
	stopCh			chan struct{}
	wg			*sync.WaitGroup
	decodeTime		time.Time
}

type CacheWorker struct {
	first		bool
	refreshTime	time.Time
	IDCache		map[uint64]*ID
}

//ID identifies a single container running in a Kubernetes Pod
type ID struct {
	Namespace     string
	PodName       string
	PodUID        string
	PodLabels     map[string]string
	PodLabelString string
	ContainerID   string
	ContainerName string
}

type podList struct {
	// We only care about namespace, serviceAccountName and containerID
	Metadata struct {
	} `json:"metadata"`
	Items []struct {
		Metadata struct {
			Namespace string            `json:"namespace"`
			Name      string            `json:"name"`
			UID       string            `json:"uid"`
			Labels    map[string]string `json:"labels"`
		} `json:"metadata"`
		Spec struct {
			ServiceAccountName string `json:"serviceAccountName"`
		} `json:"spec"`
		Status struct {
			ContainerStatuses []struct {
				ContainerID string `json:"containerID"`
				Name        string `json:"name"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

var (
	cacheRefreshTime = 5 * time.Second
	kubePattern   = regexp.MustCompile(`\d+:.+:/kubepods/[^/]+/pod[^/]+/([0-9a-f]{64})`)
	dockerPattern = regexp.MustCompile(`\d+:.+:/docker/pod[^/]+/([0-9a-f]{64})`)
	kubeletPort = 10255
)

func (k *KubePod) CacheWorkerRun() {
	k.wg.Add(1)
	defer k.wg.Done()

	for {
		select {
		case <-k.stopCh:
			log.Printf("cache worker stop")
			return
		default:
			k.refreshCache()
		}
	}
}

func (k *KubePod) EnsureWorkerRun() (error){
	k.workerMu.Lock()
	defer func() {
		k.workerMu.Unlock()
	}()

	if !k.cacheWorkerRunning {
		k.wg = &sync.WaitGroup{}
		k.stopCh = make(chan struct{})

		k.cacheWorker = CacheWorker {
			first:		true,
			IDCache:	map[uint64]*ID{},
		}
		go k.CacheWorkerRun()
		go func() {
			signalChan := make(chan os.Signal, 1)
			signal.Notify(signalChan, syscall.SIGKILL)
			<-signalChan
			close(k.stopCh)

		}()
		k.cacheWorkerRunning = true
	}
	return nil
}

func (k *KubePod) Decode(in []byte, conf config.Decoder)([]byte, error) {
	if err := k.EnsureWorkerRun(); err != nil {
		return nil, err
	}

	pid, err := strconv.Atoi(string(in))
	if err != nil {
		return nil, err
	}

	k.decodeTime = time.Now()

	value := []byte("")
	if id, ok := k.cacheWorker.IDCache[uint64(pid)]; ok {
		value = []byte(fmt.Sprintf("kubepod,pid=%d,namespace:%s,podname=%s,labels=%s",
			pid, id.Namespace, id.PodName, id.PodLabelString))
	} else {
		value = []byte(fmt.Sprintf("host,pid=%d", pid))
	}
	return value, nil
}

func (k *KubePod)refreshCache() {
	now := time.Now()
	if k.cacheWorker.first {
		k.cacheWorker.first = false
	} else if k.cacheWorker.refreshTime.Add(cacheRefreshTime).After(now) {
		time.Sleep(cacheRefreshTime)
		return
	} 

	if k.decodeTime.Add(cacheRefreshTime).Before(now) {
		time.Sleep(cacheRefreshTime)
		return
	}

	k.cacheWorker.refreshTime = now
	log.Printf("refreshCache() %v", now)

	processes, err := ps.Processes()
	if err != nil {
		log.Printf("could not list processes: %v", err)
		return
	}

	// Look up the container ID in the local kubelet API.
	resp, err := http.Get(fmt.Sprintf("http://localhost:%v/pods", kubeletPort))
	if err != nil {
		log.Fatalf("could not lookup container ID in kubelet API")
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("could not read response from kubelet API")
		return
	}
	var podInfo *podList
	if err := json.Unmarshal(body, &podInfo); err != nil {
		log.Fatalf("could not unmarshal response from kubelet API")
		return
	}

	for _, proc := range processes {
		pid := proc.Pid()
		cid, err := LookupDockerContainerID(pid)
		if err != nil {
			continue	
		}

		for _, item := range podInfo.Items {
			for _, status := range item.Status.ContainerStatuses {
				if status.ContainerID == "docker://"+cid ||
					status.ContainerID == "containerd://"+cid {
					labels := ""
					for l, v := range item.Metadata.Labels {
						labels += l+":"+v+","
					}
					k.cacheWorker.IDCache[uint64(pid)] = &ID{
						Namespace:     item.Metadata.Namespace,
						PodName:       item.Metadata.Name,
						PodUID:        item.Metadata.UID,
						PodLabels:     item.Metadata.Labels,
						PodLabelString:labels,
						ContainerID:   cid,
						ContainerName: status.Name,
					}
				}
			}
		}
	}
}

// returning its Docker container ID.
func LookupDockerContainerID(pid int) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		// this is normal, it just means the PID no longer exists
		return "", nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := dockerPattern.FindStringSubmatch(line)
		if parts != nil {
			return parts[1], nil
		}
		parts = kubePattern.FindStringSubmatch(line)
		if parts != nil {
			return parts[1], nil
		}
	}
	return "", nil
}
