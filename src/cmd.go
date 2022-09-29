package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "",
		Short: "a http gateway",
		Long:  `kuafu is a http gateway supports dynamic upstream routing, security enhance, static file serving.`,
		Run: func(cmd *cobra.Command, args []string) {
			startServer()
		},
	}
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "check if  the configuration file is valid",
	Long:  "check if  the configuration file is valid",
	Run: func(cmd *cobra.Command, args []string) {
		checkConfig()
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
	Use:   "startServer",
	Short: "startServer kuafu proxy server",
	Long:  "startServer kuafu proxy server ",
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
}
func Init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "/etc/kuafu.toml", "config file (default is /etc/kuafu.toml)")
	rootCmd.PersistentFlags().StringVar(&privateKeyFile, "private-key", "~/.ssh/id_rsa", "ssh private key file path")
	rootCmd.PersistentFlags().StringVar(&sshPassword, "ssh-password", "", "ssh private key password")

	rootCmd.AddCommand(versionCmd)

	testCmd.PersistentFlags().StringVar(&configFile, "config", "/etc/kuafu.toml", "config file (default is /etc/kuafu.toml)")
	rootCmd.AddCommand(testCmd)

	runCmd.PersistentFlags().StringVar(&configFile, "config", "/etc/kuafu.toml", "config file (default is /etc/kuafu.toml)")
	runCmd.PersistentFlags().StringVar(&privateKeyFile, "private-key", "~/.ssh/id_rsa", "ssh private key file path")
	runCmd.PersistentFlags().StringVar(&sshPassword, "ssh-password", "", "ssh private key password")

	rootCmd.AddCommand(runCmd)
}

func initConfig() {

}
