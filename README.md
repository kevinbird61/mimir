# Mímir

Researching work on *anomaly detection* with SDN (software-defined network) / PDP (programmable data plane), which is named `Mímir`.

**Mímir** (Old Norse "The rememberer, the wise one") or Mim is a figure in Norse mythology, renowned for his **knowledge and wisdom**, who is beheaded during the Æsir-Vanir War. Afterward, the god Odin carries around Mímir's head and it recites secret knowledge and counsel to him.

## Project Layout

Planning of our project layout of MIMIR. 

```
.
├── eva                             # Collection of Evaluation-related methodology 
├── of                              # Collection of OpenFlow scenario
├── p4                              # Collection of P4 scenario/methodology
│   ├── tool-diff
│   |   ├── polling-based
│   |   ├── pushing-based
│   ├── algo-diff
│   |   ├── TRW-CB
│   |   ├── entropy-based
│   |   ├── OpenWatch
│   |   ├── volume-based
│   ├── sys-diff
│   |   ├── single-switch
│   |   ├── multi-switches
│   ├── gran-diff
│   |   ├── sampling
│   |   ├── flowlet
│   ├── basic-p4-template           # Basic p4 switch template source code, copy-and-paste to new scenario.
│   ├── main-ids                    # Mímir's main program goes here
│   ├── other                       
│   └── utils
├── plot                            # Plot the evaluation result
├── env                             # Building the virtual network environment with docker container by golang & shell scripts.
├── resource                        # Gliffy, image sources used in this repository
├── dataset                         # Description of the traffic data (e.g. How to record the traffic? ... etc) used in Mímir
├── malware                         # Implementation/Discussion of Malware or Attacking pattern packet generator.
└── paper                           # After finish Mímir, the LaTeX files will go here.
```

## Explanation of project layout

| Folder Path/Name | Purpose | Note | Maintainer | Progress |
| --- | --- | --- | --- | --- |
| `eva` | Evaluation of our scenario/pcap files. Aim to make the ground truth of our experiments. | x | kevinbird61 | |
| `of` | Scenario of OpenFlow version. | x | | |
| `p4` | Scenario of P4 version. | x | kevinbird61 | |
| `resource` | Images, flowchart, explanation of program, useful documents, tutorials will place in here. | x | | |
| `dataset` | Download links of our source pcap files, and the evaluation of each pcap file (e.g. represent as its **ground truth**). Also these pcap files represent as benign traffic in our experiments. | Using *tcpdump/cisco flow recorder* to record the real traffic from real world. | kevinbird61 | |
| `malware` | Attack pattern generator. | x | kevinbird61 | | 
| `paper` | Paper work of MIMIR. Using LaTeX as our tool to write the paper. |  x | kevinbird61 | |