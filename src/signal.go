package main

import (
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

func readPidFile(file_path string) (int, error) {
	data, err := ioutil.ReadFile(file_path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return 0, err
	}
	return pid, nil
}

// writePidFile 将当前进程的进程号写入文件
func writePidFile(filePath string) error {
	pid := os.Getpid()
	return ioutil.WriteFile(filePath, []byte(strconv.Itoa(pid)), 0644)
}

/**
 * waiting for USR1 signal and reload config file
 */
func waitUsr1Signal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGUSR1)
	go func() {
		for {
			<-sigs
			if hotUpdateMapFile() {
				Info("hot update map file success")
			} else {
				Info("hot update map file failed")
			}
		}
	}()
}
