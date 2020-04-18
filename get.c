/*	
 * Access Control	
 *	
 * The basic idea is that a file owner will dictate (read) access to their file named basename.ext by specifying	
 * users that are allowed access and the type of access each user is allowed in a file named basename.ext.access.	
 * So, a user wishing to protect daily schedule.txt would create a file named daily schedule.txt.access.	
 * Users gain read access to protected files via the SUID binary get (that you will write) and which the	
 * file owner will place in an appropriate location. While the access files will include the ability to specify	
 * a user should be granted write access, you will not be required to implement a put program. If the file	
 * basename.ext.access does not exist, no access is allowed via get (or put). 	
 *	
 */	

#define _GNU_SOURCE	
#include <unistd.h>	
#include <stdio.h>	
#include <string.h>	
#include <stdlib.h>	
#include <pwd.h>	
#include <errno.h>	
#include <fcntl.h>	
#include <sys/stat.h>	
#include <sys/sendfile.h>	


/* Global variables */ 	
FILE* aclFile;	

int source;	
int destination;	
int flag; 	

/* Close all the files upon failure exit 1 */	
void closeFail(){	
	if(aclFile) fclose(aclFile);	
	if(source)  close(source);	
	if(destination) close(destination);	
	//printf("Failed\n");	
	exit(1);	
}	

/* Close all the fiels upon success exit 1 */	
void closeSuccess(){	
	if(aclFile) fclose(aclFile);	
	if(source)  close(source);	
	if(destination) close(destination);	
	//printf("Success\n");	
	exit(1);	
}	


/* Open the source in read only mode  	
 * If failed to open the file close all the files exit. 	
 * If successfull returns the file descriptor. 	
 */	
int openSource(char* path){	
	int fd = open(path, O_RDONLY);	
	if(fd == -1)	
	{	
		//printf("Unable to open the source file.\n");	
		closeFail();	
	}	
	return fd; 	
}	

/* Open the destination file  in write only mode. If file does not exist it will be created. 	
 * the user ID of the file shall be set to the effective user ID of the process; 	
 * the group ID of the file shall be set to the group ID of the file's parent directory 	
 * or to the effective group ID of the process  	
 * If failed to open the file close all the files exit. If successfull returns the file descriptor. 	
 */	
int openDestination (char* path){	
	int fd = open (path, O_WRONLY | O_CREAT); 	
	if (fd == -1)	
	{	
		//printf("Faild to write to the desitnation file.\n");	
		closeFail();	
	}	
	return fd;	
}	

/* Tries to open the acl file, if acl file not found exit.	
 * If the file is found read the whole file line by line,	
 * storing the user and permissions respectively. 	
 * When the user is found break the loop. If the user have	
 * persmissions for the file return the permission else	
 * exit closing all the files. 	
 */ 	
char parseACL(char* path, char* username){	
	char permissions; 	
	char user[128];	
	char buffer[256];	

	aclFile = fopen(path, "r");	

	//File not found 	
	if (aclFile == NULL)	
	{	
		//printf("ACL file does not exist\n");	
		closeFail(); 	
	}	

	//Scan the file line by line	
	while(fgets(buffer, 257, aclFile) != NULL)	
	{	
		fscanf(aclFile, "%s %c", user, &permissions);	
		if(strcmp(user, "#")){	
			//printf("User: %s\t Permissions: %c\n",user, permissions);	
			if (!strcmp(user, username))	
			{	
				//printf("Username found%s\n",user);	
				break;	
			}	
		}	
	}	

	printf("Permissions%c\n", permissions);	

	//Check permissions of the user for write 	
	if((permissions != 'b') && (permissions != 'w'))	
	{	
		//printf("You do not have permissions for this file.\n");	
		closeFail();	
	}	

	return permissions;	
}	

int main(int argc, char *argv[])	
{	
	//Exit if not enough parameters provided. 	
	if(argc != 3)	
	{	
		//printf("Not enough parameters provided.\n");	
		exit(1);	
	}	

	char* srcPath = argv[1];	
	char* dstPath = argv[2];	
	char aclPath[4096];	
	int dFlag = 0; 	

	//Get the uid and euid	
	const uid_t ruid = getuid();	
	const uid_t euid = geteuid();	

	//Copy the Acl file to source and add .acess extention.	
	strcpy(aclPath, srcPath);	
	strcat(aclPath, ".access"); 	

	//Open the source file	
	source = openSource(srcPath);	

	struct stat aclStat, srcStat, dstStat; 	

	/*	
	 * int lstat(const char *pathname, struct stat *statbuf);	
	 * Pass the path and struct pointer into lstat 	
	 * check if lstat accepts the acl without error	
	 * if error (-1) exit	
	 */	
	if(lstat(aclPath, &aclStat) == -1)	
	{	
		//printf("lstat error acl file.\n");	
		closeFail();	
	}	

	//Validate source path with lstat	
	if(lstat(srcPath, &srcStat) == -1)	
	{	
		//printf("lstat error source file.\n");	
		closeFail();	
	}	

	if (lstat(dstPath, &dstStat) == -1)	
	{	
		//printf("destination file does not exist\n");	
		closeFail();	
	}	
	//File exists 	
	else	
	{	
		dFlag = 1; 	
	}	

	destination = openDestination(dstPath);	

	//Check if the file is a symbolik link 	
	if S_ISLNK(aclStat.st_mode)	
	{	
		//printf("ACL file is symbolink link.\n");	
		closeFail();	
	}	

	//Check if the file is ordinary file 	
	if(!S_ISREG(srcStat.st_mode))	
	{	
		//printf("The file is not ordinary file.\n");	
		closeFail(); 	
	}	

	/* Check the for group permission of the acl file 	
	 * S_IROTH Read permission bit for other users.	
	 * S_IWOTH Write permission bit for other users. 	
	 * S_IWGRP Write permission bit for the group owner of the file.	
	 * S_IRGRP Read permission bit for the group owner of the file.	
	 * S_IXOTH Execute or search permission bit for other users.	
	 * S_IXGRP Execute or search permission bit for the group owner of the file. 	
	 */	
	if ((aclStat.st_mode & S_IRGRP) ||	
	(aclStat.st_mode & S_IROTH) ||	
	(aclStat.st_mode & S_IWOTH) ||	
	(aclStat.st_mode & S_IWGRP) ||	
	(aclStat.st_mode & S_IXGRP) ||	
	(aclStat.st_mode & S_IXOTH)) {	
		//printf("Acl file should not have group access.\n");	
		closeFail();	
	}	

	//Change euid to ruid	
	if (seteuid(ruid) < 0) {	
		//printf("Failed to change euid to ruid\n");	
		closeFail();	
	}	

	/* Check for the euid read acess to source file 	
	 * R_OK Flag meaning test for read permission	
	 */	
	if (!euidaccess(srcPath, R_OK)){	
		//printf("euid does not have read acess.\n");	
		closeFail();	
	}	

	/* Check for the euid write acess to destination file 	
	 * W_OK Flag meaning test for write permission	
	 */	
	if (!euidaccess(dstPath, W_OK)) {	
		//printf("euid does not have write acess to destination\n");	
		closeFail();	
	}	

	if (!euidaccess(aclPath, R_OK))	
	{	
		//printf("ruid cannot write to acl\n");	
		closeFail();	
	}	

	//Chnage euid back to euid	
	if(setuid(euid)<0)	
	{	
		//printf("Failed to change euid back to euid\n");	
	}	

	if(srcStat.st_uid != geteuid()){	
		//printf("Source is not owned by euid\n");	
		closeFail();	
	}	

	char* username;	

	/*function returns a pointer to a structure containing the 	
	 *broken-out fields of the record in the password database	
	 *that matches the user ID uid. 	
	 */		

	struct passwd* pw = getpwuid(ruid);	

	//Match the username in the struct passwd	
	if(pw)	
	{	
		username = pw->pw_name;	
	}	
	else	
	{	
		//printf("Username not found\n");	
		closeFail();	
	}	

	//If destination already exists, the user is quired for overwritting	
	if(dFlag){	
		char userAns;	
		while(1)	
		{	
			printf("File exixts. Do you want to Overwrite? (Y/N)\n");	
			scanf(" %c", &userAns);	
			if(userAns == 'N' || userAns == 'n')	
			{	
				closeFail();	
			}	
			if(userAns == 'Y' || userAns == 'y')	
			{	
				break;	
			}	
			else	
			{	
				printf("Invalid answer\n");	
			}	
		}	
	}	

	//Read the acl file	
	parseACL(aclPath, username);	

	//Send the data 	
	int sentData = sendfile(destination, source, NULL, srcStat.st_size*sizeof(int));	
	if (sentData == -1)	
	{	
		//printf("Failed to send data.\n");	
		closeFail();	
	}	
	else	
	{	
		//printf("Data sent.\n");	
	}	

	//Close with success 	
	closeSuccess();	
}
