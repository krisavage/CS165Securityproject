Krishna Ganapathi
860924522	
cs165-A2

open 2 terminals. on one navigate to folder with client.cpp and on the other navigate to the folder with server.cpp(should be in server folder)



How to compile client
g++ client.cpp -o client -l ssl -l crypto

How to compile server 
g++ server.cpp -o client -l ssl -l crypto

How to run server (RUN SERVER FIRST)
server -port portnumber (where portnumber is your portnumber)

How to run client(RUN CLIENT SECOND)
client -server servername -port portnumber filename (where servername is your servername portnumber is your portnumber and filename is ganapathi.txt)
