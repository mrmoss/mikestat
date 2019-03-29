//Mikestat
//Written By: Mike Moss
//Netstat like program, with an automatic "-tulpan" option.

#include <ctype.h>
#include <dirent.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

char titles[7][435]=
{
	"                )              )          )  \n"
	"    )    (   ( /(    (      ( /(    )  ( /(  \n"
	"   (     )\\  )\\())  ))\\ (   )\\())( /(  )\\()) \n"
	"   )\\  '((_)((_)\\  /((_))\\ (_))/ )(_))(_))/  \n"
	" _((_))  (_)| |(_)(_)) ((_)| |_ ((_)_ | |_   \n"
	"| '  \\() | || / / / -_)(_-<|  _|/ _` ||  _|  \n"
	"|_|_|_|  |_||_\\_\\ \\___|/__/ \\__|\\__,_| \\__|  \n"
	,
	"\n"
	"        .__ __                    __          __   \n"
	"  _____ |__|  | __ ____   _______/  |______ _/  |_ \n"
	" /     \\|  |  |/ // __ \\ /  ___/\\   __\\__  \\\\   __\\\n"
	"|  Y Y  \\  |    <\\  ___/ \\___ \\  |  |  / __ \\|  |  \n"
	"|__|_|  /__|__|_ \\\\___  >____  > |__| (____  /__|  \n"
	"      \\/        \\/    \\/     \\/            \\/      \n"
	,
	"\n\n"
	"           _ _             _        _   \n"
	" _ __ ___ (_) | _____  ___| |_ __ _| |_ \n"
	"| '_ ` _ \\| | |/ / _ \\/ __| __/ _` | __|\n"
	"| | | | | | |   <  __/\\__ \\ || (_| | |_ \n"
	"|_| |_| |_|_|_|\\_\\___||___/\\__\\__,_|\\__|\n"
	,
	"\n\n\n"
	"       _ _           _       _   \n"
	" _____|_| |_ ___ ___| |_ ___| |_ \n"
	"|     | | '_| -_|_ -|  _| .'|  _|\n"
	"|_|_|_|_|_,_|___|___|_| |__,|_|  \n"
	,
	"\n\n"
	"              _ __             __        __ \n"
	"   ____ ___  (_) /_____  _____/ /_____ _/ /_\n"
	"  / __ `__ \\/ / //_/ _ \\/ ___/ __/ __ `/ __/\n"
	" / / / / / / / ,< /  __(__  ) /_/ /_/ / /_  \n"
	"/_/ /_/ /_/_/_/|_|\\___/____/\\__/\\__,_/\\__/  \n"
	,
	"\n\n"
	" __    __     __     __  __     ______     ______     ______   ______     ______  \n"
	"/\\ \"-./  \\   /\\ \\   /\\ \\/ /    /\\  ___\\   /\\  ___\\   /\\__  _\\ /\\  __ \\   /\\__  _\\ \n"
	"\\ \\ \\-./\\ \\  \\ \\ \\  \\ \\  _\"-.  \\ \\  __\\   \\ \\___  \\  \\/_/\\ \\/ \\ \\  __ \\  \\/_/\\ \\/ \n"
	" \\ \\_\\ \\ \\_\\  \\ \\_\\  \\ \\_\\ \\_\\  \\ \\_____\\  \\/\\_____\\    \\ \\_\\  \\ \\_\\ \\_\\    \\ \\_\\ \n"
	"  \\/_/  \\/_/   \\/_/   \\/_/\\/_/   \\/_____/   \\/_____/     \\/_/   \\/_/\\/_/     \\/_/ \n"
	,
	"              __                      __             __      \n"
	"           __/\\ \\                    /\\ \\__         /\\ \\__   \n"
	"  ___ ___ /\\_\\ \\ \\/'\\      __    ____\\ \\ ,_\\    __  \\ \\ ,_\\  \n"
	"/' __` __`\\/\\ \\ \\ , <    /'__`\\ /',__\\\\ \\ \\/  /'__`\\ \\ \\ \\/  \n"
	"/\\ \\/\\ \\/\\ \\ \\ \\ \\ \\\\`\\ /\\  __//\\__, `\\\\ \\ \\_/\\ \\L\\.\\_\\ \\ \\_ \n"
	"\\ \\_\\ \\_\\ \\_\\ \\_\\ \\_\\ \\_\\ \\____\\/\\____/ \\ \\__\\ \\__/.\\_\\\\ \\__\\\n"
	" \\/_/\\/_/\\/_/\\/_/\\/_/\\/_/\\/____/\\/___/   \\/__/\\/__/\\/_/ \\/__/\n"
};

void* mem_grow(void* buf,const size_t block,size_t* count)
{
	void* real_buf=NULL;
	size_t blocks=0;

	if(buf!=NULL)
	{
		real_buf=(char*)buf-sizeof(size_t);
		blocks=*(size_t*)real_buf;
	}

	if(*count+1>=blocks)
		blocks=(*count+1)*2;

	real_buf=realloc(real_buf,sizeof(size_t)+block*blocks);

	if(real_buf==NULL&&*count+1>0)
		*count=0;
	else
		++(*count);

	*(size_t*)real_buf=blocks;
	return (char*)real_buf+sizeof(size_t);
}

void* mem_shrink(void* buf,const size_t block,size_t* count)
{
	if(*count==0)
		*count=1;
	else
		--(*count);

	return buf;
}

void mem_free(void* buf)
{
	void* real_buf=NULL;

	if(buf!=NULL)
		real_buf=(char*)buf-sizeof(size_t);

	free(real_buf);
}

struct pid_lookup_t
{
	uint32_t pid;
	off_t ino;
};

struct conn_t
{
	uint8_t tcp;
	uint8_t v6;
	uint32_t pid;
	uint16_t lport;
	uint16_t rport;
	uint8_t laddr[16];
	uint8_t raddr[16];
	uint8_t state;
};

int get_socket_ino(const char* path,off_t* ino)
{
	char link[15];
	memset(link,0,15);
	ssize_t size=-1;

	if(sizeof(off_t)!=4&&sizeof(off_t)!=8)
		return -1;

	size=readlink(path,link,15);

	if(size==-1)
		return -1;

	while(size>0&&isspace(link[size-1])!=0)
		link[size-1]=0;

	if(sizeof(off_t)==4&&sscanf(link,"socket:[%"SCNu32"]",(uint32_t*)ino)!=1)
		return 1;
	if(sizeof(off_t)==8&&sscanf(link,"socket:[%"SCNu64"]",(uint64_t*)ino)!=1)
		return 1;

	return 0;
}

int get_pid_inos(const uint32_t pid,struct pid_lookup_t** buf,size_t* count)
{
	const uint32_t max_path_len=300;
	char path[max_path_len];
	DIR* dp=NULL;
	struct dirent* np=NULL;
	struct pid_lookup_t temp;

	memset(path,0,max_path_len);
	snprintf(path,max_path_len,"/proc/%"PRIu32"/fd",pid);
	dp=opendir(path);
	temp.ino=0;
	temp.pid=pid;

	while(dp!=NULL)
	{
		if((np=readdir(dp))==NULL)
			return closedir(dp);

		memset(path,0,max_path_len);
		snprintf(path,max_path_len,"/proc/%"PRIu32"/fd/%s",pid,np->d_name);

		if(get_socket_ino(path,&temp.ino)==0&&temp.ino!=0)
		{
			if((*buf=(struct pid_lookup_t*)mem_grow(*buf,sizeof(struct pid_lookup_t),count))==NULL)
				return closedir(dp);

			(*buf)[*count-1].ino=temp.ino;
			(*buf)[*count-1].pid=temp.pid;
			temp.ino=0;
		}
	}

	return 0;
}

int get_pids(struct pid_lookup_t** buf,size_t* count)
{
	DIR* dp=opendir("/proc");
	struct dirent* np=NULL;
	uint32_t temp=0;

	*buf=NULL;
	*count=0;

	while(dp!=NULL)
	{
		if((np=readdir(dp))==NULL)
			return closedir(dp);

		if(np->d_type==DT_DIR&&sscanf(np->d_name,"%"SCNu32,&temp)==1&&temp!=0)
		{
			if(get_pid_inos(temp,buf,count)!=0)
				return closedir(dp);

			temp=0;
		}
	}

	return -1;
}

int skip_line(FILE* file)
{
	int temp=0;

	while(1)
	{
		temp=fgetc(file);

		if(temp<0)
			return -1;
		if(temp==(int)'\n')
			break;
	}

	return 0;
}

size_t read_hex_array(FILE* file,uint8_t* buf,const size_t count)
{
	size_t ii=0;

	for(ii=0;ii<count;++ii)
		if(fscanf(file,"%2hhX",buf+ii)!=1)
			break;

	return ii;
}

void ntohs(uint8_t addr[16],const int v6)
{
	int ii=0;
	uint8_t temp8=0;
	uint16_t temp16=0;

	if(v6!=0)
	{
		for(ii=0;ii<4;++ii)
		{
			temp16=*(uint16_t*)(addr+ii*4+0);
			*(uint16_t*)(addr+ii*4+0)=*(uint16_t*)(addr+ii*4+2);
			*(uint16_t*)(addr+ii*4+2)=temp16;
		}
	}
	else
	{
		for(ii=0;ii<2;++ii)
		{
			temp8=addr[ii];
			addr[ii]=addr[3-ii];
			addr[3-ii]=temp8;
		}
	}
}

void get_type(const struct conn_t* conn,char buf[5])
{
	if(conn->tcp!=0)
		snprintf(buf,4,"tcp");
	else
		snprintf(buf,4,"udp");
	if(conn->v6!=0)
		snprintf(buf+3,2,"6");
	else
		snprintf(buf+3,2,"4");
}

void get_proc_filename(const int tcp,const int v6,char buf[15])
{
	memset(buf,0,15);
	snprintf(buf,11,"/proc/net/");
	struct conn_t temp;
	temp.tcp=tcp;
	temp.v6=v6;
	get_type(&temp,buf+10);

	if(temp.v6==0)
		buf[13]=0;
}

void get_state(const struct conn_t* conn,char buf[12])
{
	memset(buf,0,12);

	if(conn->tcp==0)
	{
		snprintf(buf,12,"-");
		return;
	}

	switch(conn->state)
	{
		case 1:
			snprintf(buf,12,"ESTABLISHED");
			break;
		case 2:
			snprintf(buf,12,"SYN_SENT");
			break;
		case 3:
			snprintf(buf,12,"SYN_RECV");
			break;
		case 4:
			snprintf(buf,12,"FIN_WAIT1");
			break;
		case 5:
			snprintf(buf,12,"FIN_WAIT2");
			break;
		case 6:
			snprintf(buf,12,"TIME_WAIT");
			break;
		case 7:
			snprintf(buf,12,"CLOSE");
			break;
		case 8:
			snprintf(buf,12,"CLOSE_WAIT");
			break;
		case 9:
			snprintf(buf,12,"LAST_ACK");
			break;
		case 10:
			snprintf(buf,12,"LISTEN");
			break;
		case 11:
			snprintf(buf,12,"CLOSING");
			break;
		default:
			snprintf(buf,12,"UNKNOWN");
			break;
	}
}

int get_net(const int tcp,const int v6,struct conn_t** buf,size_t* count,struct pid_lookup_t* pids,const size_t pid_count)
{
	char filename[15];
	FILE* file=NULL;
	size_t addr_size=4;
	size_t ii=0;
	off_t temp_ino=0;
	struct conn_t* conn=NULL;
	int skipd=0;
	uint32_t skip32=0;
	uint8_t skip8=0;

	get_proc_filename(tcp,v6,filename);
	file=fopen(filename,"r");
	*count=0;
	*buf=NULL;

	if(v6!=0)
		addr_size=16;

	if(file==NULL||skip_line(file)!=0)
		return -1;

	while(1)
	{
		if((*buf=(struct conn_t*)mem_grow(*buf,sizeof(struct conn_t),count))==NULL)
			return -1;

		conn=(*buf)+*count-1;

		if(fscanf(file,"%*[ \n\t]%d:%*[ \n\t]",&skipd)!=1||
			read_hex_array(file,conn->laddr,addr_size)!=addr_size||fscanf(file,":%4hX",&conn->lport)!=1||
			read_hex_array(file,conn->raddr,addr_size)!=addr_size||fscanf(file,":%4hX",&conn->rport)!=1||
			fscanf(file,"%*[ \n\t]%2hhX",&conn->state)!=1||
			fscanf(file,"%*[ \n\t]%8X:%8X%*[ \n\t]%2hhX:%8X%*[ \n\t]%8X%*[ \n\t]%d%*[ \n\t]%d",&skip32,&skip32,&skip8,&skip32,&skip32,&skipd,&skipd)!=7||
			fscanf(file,"%*[ \n\t]%lu",&temp_ino)!=1||
			skip_line(file)!=0)
		{
			if((*buf=(struct conn_t*)mem_shrink(*buf,sizeof(struct conn_t),count))==NULL)
				return -1;

			break;
		}

		conn->tcp=tcp;
		conn->v6=v6;
		ntohs(conn->laddr,v6);
		ntohs(conn->raddr,v6);

		conn->pid=0;

		for(ii=0;ii<pid_count;++ii)
		{
			if(pids[ii].ino==temp_ino)
			{
				conn->pid=pids[ii].pid;
				break;
			}
		}
	}

	fclose(file);

	return 0;
}

void stringify_net(char* buf,const uint8_t* addr,const uint16_t port,const int v6)
{
	memset(buf,0,45);

	if(v6)
		snprintf(buf,45,"%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%hu",
			*(uint16_t*)(addr),*(uint16_t*)(addr+2),*(uint16_t*)(addr+4),*(uint16_t*)(addr+6),
			*(uint16_t*)(addr+8),*(uint16_t*)(addr+10),*(uint16_t*)(addr+12),*(uint16_t*)(addr+14),
			port);
	else
		snprintf(buf,45,"%u.%u.%u.%u:%hu",addr[0],addr[1],addr[2],addr[3],port);
}

void print_title()
{
	int index=-1;
	srand(time(NULL));

	while(index<0||index>6)
		index=(rand()+rand()+rand()+rand()/4)%7;

	printf("%s\n",titles[index]);
	printf("%-4s %-45s %-45s %-11s %-10s\n","type","local","remote","state","pid");
	printf("%-4s %-45s %-45s %-11s %-10s\n","----","-----","------","-----","---");
}

void print_net(const struct conn_t* buf,const size_t count)
{
	size_t ii=0;
	char type_str[5];
	char laddr[45];
	char raddr[45];
	char state_str[12];

	for(ii=0;ii<count;++ii)
	{
		get_type(buf+ii,type_str);
		stringify_net(laddr,buf[ii].laddr,buf[ii].lport,buf[ii].v6);
		stringify_net(raddr,buf[ii].raddr,buf[ii].rport,buf[ii].v6);
		get_state(buf+ii,state_str);

		printf("%-4s %-45s %-45s %-11s %-10"PRIu32"\n",type_str,laddr,raddr,state_str,buf[ii].pid);
	}
}

int main()
{
	int options[4][2]={{1,0},{0,0},{1,1},{0,1}};
	size_t pid_count=0;
	size_t count=0;
	int ii=0;
	struct pid_lookup_t* pids=NULL;
	struct conn_t* conns=NULL;

	if(get_pids(&pids,&pid_count)!=0)
	{
		printf("ERROR!\n");
		return 1;
	}

	print_title();

	for(ii=0;ii<4;++ii)
	{
		if(get_net(options[ii][0],options[ii][1],&conns,&count,pids,pid_count)!=0)
		{
			printf("Error getting ");
			if(options[ii][0]!=0) printf("tcp");else printf("udp");
			if(options[ii][1]!=0) printf("6"); else printf("4");
			printf(" connections!\n");
			return 1;
		}

		print_net(conns,count);
		mem_free(conns);
		count=0;
		conns=NULL;
	}

	pid_count=0;
	mem_free(pids);

	return 0;
}
