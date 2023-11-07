#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <crypt.h>
#include<ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>


#define MAX_FILENAME_LEN 256
#define STORAGE_DIRECTORY "./clientfiles/"
char salt[] = "12";
struct FileInfo {
    char filename[256];
    long size;
    time_t last_modified;
    char uploader[256];
    char last_downloader[256];
    int num_downloads;
    int download_status; // 0 for not downloaded, 100 for fully downloaded
};
void displayMenu() {
    printf("\n----- Menu -----\n");
    printf("1. Download File\n");
    printf("2. Upload File\n");
    printf("3. Display All Files\n");
    printf("4. Display my Uploaded Files\n");
    printf("5. Remove File\n");
    printf("6. Manage Account (Change Password)\n");
    printf("7. Exit\n");
    printf("Enter your choice: ");
}
void displayLog()
{
    printf("\n-------Welcome to the File Sharing System------\n");
    printf("1. Login\n");
    printf("2. Create an Account\n");
    printf("3. Exit\n");
    printf("Enter your choice: ");
}


void hPassword(const char* password, char* hashedPassword) {
    char* hashed = crypt(password, salt);
    strcpy(hashedPassword, hashed);
}

int isValidUsername(const char* username) {
    // Check if the username contains only alphanumeric characters
    for (int i = 0; username[i] != '\0'; i++) {
        if (!isalnum(username[i])) {
            return 0; // Invalid username
        }
    }
    return 1; // Valid username
}
void registerNewAccount(int client_socket) {
    char username[256];
    char newPassword[256];
    char hashedPassword[256];
    char salt[256];
    int exceed;
    recv(client_socket, &exceed, sizeof(int), 0);
    if(!exceed)
    {
        int valid=0;

        while(!valid)
        {
            printf("Enter your new username: ");
            scanf("%s", username);
            // Check the validity of the username
            if (!isValidUsername(username)) {
                printf("Invalid username format. Please use alphanumeric characters only.\n");
            }
            else
                valid=1;

        }
        
        printf("Enter your new password: ");
        scanf("%s", newPassword);

        hPassword(newPassword, hashedPassword);
        // Send username and hashed password to the server for registration
        send(client_socket, username, sizeof(username), 0);
        //send(client_socket, salt, sizeof(salt), 0);
        send(client_socket, hashedPassword, sizeof(hashedPassword), 0);
        char registrationResult[256];
        recv(client_socket, registrationResult, sizeof(registrationResult), 0);
        printf("%s\n", registrationResult);

    }
    else
        printf("Maximum user limit exceeded.No more new registrations are possible!!!\n");
}

int main() {
    int client_socket;
    struct sockaddr_in server_addr;
    struct timeval timeout;

    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set up server address struct
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345); // Server port number
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Server IP address

    // Connect to the server
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connection failed");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    char username[256];
    char salt[256];
    char password[256];
    char hashedPassword[256];
    char newPassword[256];
    char msg[256];
    int choice;
    int loggedIn = 0;
    char command[256];

    while (!loggedIn) {
        memset(command, 0, sizeof(command));
        displayLog();
        scanf("%d", &choice);
        switch(choice)
        {
            case 1: strcpy(command, "login");
                    send(client_socket, command, strlen(command), 0);
                    printf("Enter your username: ");
                    scanf("%s", username);
                    send(client_socket, username, sizeof(username), 0);
                    printf("Enter your password: ");
                    scanf("%s", password);
                    hPassword(password, hashedPassword);
                    send(client_socket, hashedPassword, sizeof(hashedPassword), 0);
                    char authResult[1];
                    recv(client_socket,authResult,sizeof(authResult),0);
                    //printf("%s\n", authResult);
                    if (authResult[0] == '1') {
                        printf("Login successful!\n");
                        loggedIn = 1;
                    } else {
                        printf("Authentication failed. Please try again.\n");
                    }
                    break;
            case 2: strcpy(command, "newregister");
                    send(client_socket, command, sizeof(command), 0);
                    registerNewAccount(client_socket);
                    break;
            case 3: // Exit the program
                    close(client_socket);
                    exit(EXIT_SUCCESS);
            default: printf("Invalid choice. Please try again.\n");
        }
    }
    if (loggedIn) {
        char downloadCommand[256] = "download";
        char uploadCommand[256] = "upload";
        char listCommand[256] = "list";
        char removeCommand[256] = "remove";
        char changePasswordCommand[256]="changepassword";
        char exitCommand[256]="exit";
        char filename[256];
        char buffer[1024];
        char full_path[512];
        char newPassword[256];
        int num_files;
        int error;
        while (1) {
            memset(buffer, 0, sizeof(buffer));
            memset(full_path, 0, sizeof(full_path));
            displayMenu();
            scanf("%d", &choice);

            switch (choice) {
                case 1: int download=0;
                        send(client_socket, downloadCommand, sizeof(downloadCommand), 0);
                        while(!download)
                        {
                            // Logic for downloading file
                            printf("Enter the filename to download: ");
                            scanf("%s", filename);
                            send(client_socket, filename, sizeof(filename),0);
                            char errorMessage[1];
                            recv(client_socket, errorMessage, sizeof(errorMessage), 0);

                            if (errorMessage[0] == '0') {
                                // File not found on the server, handle this case
                                printf("File not found on the server.\n");
                            }
                            else
                            {
                                download=1;
                            }

                        }
                        snprintf(full_path, sizeof(full_path), "%s%s", STORAGE_DIRECTORY, filename);
                        // Receive the file size
                        long file_size;
                        recv(client_socket, &file_size, sizeof(long),0);

                        // Receive the file data
                        FILE *file = fopen(full_path, "wb");
                        if (file == NULL) {
                            perror("Error opening file");
                        }

                        int bytes_received;
                        while (file_size > 0) {
                            bytes_received = recv(client_socket, buffer, sizeof(buffer),0);
                            fwrite(buffer, 1, bytes_received, file);
                            file_size -= bytes_received;
                        }

                        printf("File '%s' downloaded successfully.\n", filename);

                        fclose(file);
                        break;

                case 2:
                    // Logic for uploading file
                    // Inside the case 2 block (Upload File)
                    int upload=0;
                    send(client_socket, uploadCommand, sizeof(uploadCommand), 0);
                    while(!upload)
                    {
                        memset(full_path, 0, sizeof(full_path));
                        printf("Enter the filename to upload: ");
                        scanf("%s", filename);
                        snprintf(full_path, sizeof(full_path), "%s%s", STORAGE_DIRECTORY, filename);
                        if (access(full_path, F_OK) == -1) {
                            // File does not exist, send an error message to the client
                            printf("File '%s' not found.\n", filename);
                        }
                        else
                        {
                            upload=1;
                            send(client_socket, filename, sizeof(filename),0);
                        }
                    }
                    recv(client_socket, &error, sizeof(int), 0);
                    if(!error)
                    {
                        // Send the file size first
                        FILE *file1 = fopen(full_path, "rb");
                        if (file1 == NULL) {
                            perror("Error opening file");
                        }

                        fseek(file1, 0, SEEK_END);
                        long file_size1 = ftell(file1);
                        fseek(file1, 0, SEEK_SET);

                        send(client_socket, &file_size1, sizeof(long),0);

                        int bytes_read;
                        while ((bytes_read = fread(buffer, 1, sizeof(buffer), file1)) > 0) {
                            send(client_socket, buffer, bytes_read,0);
                        }

                        printf("File '%s' uploaded successfully.\n",filename);

                        fclose(file1);

                    }
                    else
                        printf("File '%s' already exists in server.Rename the file to upload!\n", filename);
                    break;
                case 3:
                        // Send the list command to the server
                        send(client_socket, listCommand, sizeof(listCommand), 0);
                        recv(client_socket, &num_files, sizeof(int), 0);
                        printf("\n");
                        printf("%-15s | %-10s | %-20s | %-15s | %-15s | %-10s | %-10s\n",
                                   "File Name", "Size (bytes)", "Last Modified", "Uploader", "Last Downloader", "Downloads", "Status");
                        printf("---------------------------------------------------------------------------------------------------------------\n");

                        // Receive and print individual FileInfo structures
                        for (int i = 0; i < num_files; i++) {
                            struct FileInfo file_info;
                            bytes_received = recv(client_socket, &file_info, sizeof(struct FileInfo), 0);

                            if (bytes_received <= 0) {
                                perror("Error receiving file information");
                                break;
                            }
                            char* timestamp = ctime(&file_info.last_modified);
                            timestamp[strcspn(timestamp, "\n")] = '\0';  // Remove the newline character

                            printf("%-15s | %-10ld | %-20s | %-15s | %-15s | %-10d | %-10d\n",
                                   file_info.filename, file_info.size, timestamp,
                                   file_info.uploader, file_info.last_downloader, file_info.num_downloads, file_info.download_status);

                        }
                    break;
                case 4: 
                        // Send the list command to the server
                        send(client_socket, listCommand, sizeof(listCommand), 0);
                        recv(client_socket, &num_files, sizeof(int), 0);
                        printf("%-15s | %-10s | %-20s | %-15s | %-15s | %-10s | %-10s\n",
                                   "File Name", "Size (bytes)", "Last Modified", "Uploader", "Last Downloader", "Downloads", "Status");
                        printf("---------------------------------------------------------------------------------------------------------------\n");

                        // Receive and print individual FileInfo structures
                        for (int i = 0; i < num_files; i++) {
                            struct FileInfo file_info;
                            bytes_received = recv(client_socket, &file_info, sizeof(struct FileInfo), 0);

                            if (bytes_received <= 0) {
                                perror("Error receiving file information");
                                break;
                            }
                            if(strcmp(file_info.uploader,username)==0)
                            {
                                char* timestamp = ctime(&file_info.last_modified);
                                timestamp[strcspn(timestamp, "\n")] = '\0';  // Remove the newline character

                                printf("%-15s | %-10ld | %-20s | %-15s | %-15s | %-10d | %-10d\n",
                                       file_info.filename, file_info.size, timestamp,
                                       file_info.uploader, file_info.last_downloader, file_info.num_downloads, file_info.download_status);

                            }
                            else
                                continue;
                        }
                        break;
                case 5: 
                        send(client_socket, removeCommand, sizeof(removeCommand), 0);
                           
                        printf("Enter the filename to remove(Only files uploaded by you can be removed): ");
                        scanf("%s", filename);
                        send(client_socket, filename, sizeof(filename),0);
                        recv(client_socket, &error, sizeof(int), 0);

                        if (!error) {
                            // File not found on the server, handle this case
                            printf("File not found on the server or is not uploaded by you.\n");
                        }
                        else
                            printf("File %s removed successfully\n",filename);

                        break;
                case 6:
                    // Logic for managing account (change password)
                
                    send(client_socket, changePasswordCommand, sizeof(changePasswordCommand), 0);
                    // Get the new password from the user and hash it for authentication
                    printf("Enter your new password: ");
                    scanf("%s", newPassword);
                    hPassword(newPassword, hashedPassword);

                    // Send hashed new password to the server for modification
                    send(client_socket, hashedPassword, sizeof(hashedPassword), 0);
                    char changeResult[256];
                    recv(client_socket, changeResult, sizeof(changeResult), 0);
                    printf("%s\n", changeResult);
                    // ...
                    break;
                case 7:
                    // Exit the program
                    send(client_socket, exitCommand, sizeof(exitCommand), 0);
                    close(client_socket);
                    //close(client_socket_redundant);
                    exit(EXIT_SUCCESS);
                default:
                    printf("Invalid choice. Please try again.\n");
            }
        }
        
    }

return 0;
}
