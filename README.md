# Final Project 

## Overview
This project is divided into three parts, exploring various aspects of network traffic analysis. 

We apply theoretical knowledge from the course and practical analysis to identify application behaviors and simulate an attacker's perspective to detect application usage through network traffic.

## Project Structure

### Part 1: Course Material Review
- Answers to open questions about the material learned in the course.
- Documented answers are provided in a PDF file.

### Part 2: Article Analysis
- Answers to questions about the three articles.
- Documented answers are provided in a PDF file.

### Part 3: Traffic Analysis and Application Identification
- This section analyzes network traffic to draw conclusions about application behaviors. 
- Additionally, it simulates an attacker's approach to identify applications in use based on network traffic.
- **Tools & Code**: Analysis is performed using scripts located in the `src` folder.

## Code Descriptions

### Analyzing Network Traffic (`analyzing_network.py`)
- **Functionality**: Analyzes and compares basic data metrics across recordings and generates various graphs illustrating different analyses such as total packet numbers, data volume in bytes, and more.
- **Usage**:
  - **Input**: Place the recordings in the `Final_Project_network/records/records_comparing` folder.
  - Each record should be type: '.pcapng'
  - **Output**: Graphs are saved in the `res/Graphs` folder.

### Network Flow Analysis (`analyzing_network_flowpic.py`)
- **Functionality**: Analyzes packet arrival times and sizes to create Flowpic graphs for each recording.
- **Features**: Option to filter traffic by the most common IP address to analyze specific application traffic.
- **Usage**:
  - **Input**: Place recordings in the `Final_Project_network/records/all_records` folder.
  -  Each record should be type: '.pcapng'
  - choose 1 to filter by most common IP in the records 0 for no filter
  - **Output**: Depending on user selection, graphs are saved in either the `res/FlowPicsFilter` or `res/FlowPics` folder.


- we left the output graphs in the folders , if you run the code with the same name of records it will replace them,
- if you run the code with new records it will create new graphs , and it will add them to the matching folder

### To run the codes with our records:
- place the 'records' folder from the zip in the Final_Project_network folder