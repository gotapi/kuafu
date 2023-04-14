package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"syscall"
)

var (
	rootCmd = &cobra.Command{
		Use:   "",
		Short: "a http gateway",
		Long:  `kuafu is an HTTP gateway that supports dynamic upstream routing, security enhancement, static file serving.`,
	}
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "check that  the configuration file is valid",
	Long:  "check that  the configuration file is valid",
	Run: func(cmd *cobra.Command, args []string) {
		checkConfig()
	},
}

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "reload the configuration file",
	Long:  "reload the configuration file",
	Run: func(cmd *cobra.Command, args []string) {
		pid, err := readPidFile(pidFilePath)
		if err != nil {
			fmt.Println("Failed to read PID file:", pidFilePath)
			return
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			fmt.Println("Failed to find process:", pid)
			return
		}
		err = proc.Signal(syscall.SIGUSR1)
		if err != nil {
			fmt.Println("Failed to send signal:", err)
			return
		}
		fmt.Println("Reload signal sent successfully")
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "show version number",
	Long:  `show version number of kuafu`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s\n", version)
	},
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "start kuafu proxy server",
	Long:  "start kuafu proxy server ",
	Run: func(cmd *cobra.Command, args []string) {
		startServer()
	},
}

func checkConfig() {
	err := loadConfig()
	if err != nil {
		fmt.Printf("configuration load failed:%v\n", err)
	} else {
		fmt.Printf("configuration syntax check  succeed,with %d hosts\n", len(kuafuConfig.Hosts))
	}
	afterLoad()
	fmt.Printf("listenAt:%v\n", kuafuConfig.Kuafu.ListenAt)
	fmt.Printf("accessLog:%v\n", kuafuConfig.Kuafu.AccessLog)
	fmt.Printf("logfile:%v\n", kuafuConfig.Kuafu.LogFile)
	fmt.Printf("consulAddr:%v\n", kuafuConfig.Kuafu.ConsulAddr)
	fmt.Printf("fallbackAddr:%v\n", kuafuConfig.Kuafu.FallbackAddr)
	fmt.Printf("dash.prefix:%v\n", kuafuConfig.Kuafu.DashConfig.Prefix)
	fmt.Printf("dash.superUser:%v\n", kuafuConfig.Kuafu.DashConfig.SuperUser)

}

/*
initialize the command line flags
*/
func Init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "/etc/kuafu.toml", "config file (default is /etc/kuafu.toml)")
	rootCmd.PersistentFlags().StringVar(&privateKeyFile, "private-key", "~/.ssh/id_rsa", "ssh private key file path")
	rootCmd.PersistentFlags().StringVar(&sshPassword, "ssh-password", "", "ssh private key password")
	rootCmd.PersistentFlags().StringVar(&pidFilePath, "pid", pidFilePath, "config file (default is /var/run/kuafu.pid)")
	rootCmd.PersistentFlags().BoolVar(&debugMode, "debug", false, "debug mode for gin")

	rootCmd.AddCommand(versionCmd)

	rootCmd.AddCommand(testCmd)

	rootCmd.AddCommand(reloadCmd)

	rootCmd.AddCommand(runCmd)

}

func initConfig() {

}
