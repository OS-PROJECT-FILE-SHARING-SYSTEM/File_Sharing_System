# File_Sharing_System
Develop a File Sharing Platform which enables users to upload and download (Large ~GB) files to a   central local cloud like server.

****Probable Features of the system:

-Define file sharing polices (like who could access/update/modify which file)
-Visualization of set of file currently available in the server, last update time, owner/uploader, last downloader info, number of downloads, size, user specific download % status 
-A user connection may abruptly gets terminated; make suitable provisions such that on reconnection resume from the same point 
-Make provisions there will be a few (2 or 3) redundant servers to deal with server failures and load balancing.


***The system satisfy the following requirements:

-Enables user login from different terminals from different physical machines
-Enables User registration and authentication (using some hash based password)
-A user-friendly text interface
-A multithreaded platform

****To run the file sharing system:

gcc servers3.c -lpthread

gcc clients3.c -lcrypt


To see the presentation and working code video click on the link--->
https://drive.google.com/drive/folders/1Lxol_-YLT7rdHzYxto30vjkXGYgRn7Ws?usp=sharing
