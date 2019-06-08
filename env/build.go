package main

// Build the virtual environment for testing framework.
// * create benign hosts 
// * create attacker, victim (default: 1)
// * run benign (iperf)
// * run attacker 

import (
    "fmt"
    //"net/url"
    "os/exec"
    "os"
    "flag"
    "strconv"
)

// running command in bash environment (linux-based)
func exec_command(program string, args ...string) {
    cmd := exec.Command(program, args...)
    cmd.Stdin = os.Stdin;
    cmd.Stdout = os.Stdout;
    cmd.Stderr = os.Stderr;
    err := cmd.Run()

    if err != nil {
        fmt.Printf("%v\n", err)
    }
}

func create_benign_host(num int) {
    // default is creating symetric network
    // atk
    for i:=0; i< num; i++ {
        exec_command("./build.sh", "create", "user_a"+strconv.Itoa(i), "atk")
    }
    // vic
    for i:=0; i< num; i++ {
        exec_command("./build.sh", "create", "user_v"+strconv.Itoa(i), "vic")
    }
}

func create_atk(name string) { 

}

func main(){
	// Args 
    benign_hosts :=     flag.Int("b", 10, "Number of benign hosts under each network domain. (Victim/Attacker)")
    verbose :=          flag.Bool("v", false, "Verbose mode.")
    victim_ip :=        flag.String("vip", "127.0.0.1", "Victim's IP address.")
    victim_port :=      flag.Int("vport", 80, "Victim's Port number.")
    delay :=            flag.Int("d", 10, "Delay (seconds) between virtual network creation and running attack.")
    clean :=            flag.Bool("c", false, "Clean all container.")

    flag.Parse()
    
    // Print out all profile specify
    fmt.Println("============================================================")
    fmt.Println("Number of benign hosts: ", *benign_hosts)
    fmt.Println("Verbose mode: ", *verbose)
    // check IP address is valid or not
    fmt.Println("Victim IP address: ", *victim_ip)
    if *victim_port < 0 || *victim_port > 65535 {
        fmt.Println("Invalid port. Value need to set between 1~65535.")
        os.Exit(1)
    }
    fmt.Println("Victim Port number: ", *victim_port)
    fmt.Println("Delay duration: ", *delay)
    fmt.Println("============================================================")

    if *clean {
        fmt.Println("Clean all executable container.")
        exec_command("./build.sh", "clean")
    } else {
        // init 
        exec_command("./build.sh", "init")
        // first create container from pre-build docker images
        create_benign_host(*benign_hosts)
        // create attacker 
        exec_command("./build.sh", "create", "attacker", "atk")
        exec_command("./build.sh", "create", "victim", "vic")

        // run service on those virtual devices
        // running iperf server on victim (FIXME: need to change ?)
        
    }

}