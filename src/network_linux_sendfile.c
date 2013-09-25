#include "network_backends.h"

#ifdef USE_LINUX_SENDFILE

#include "network.h"
#include "fdevent.h"
#include "log.h"
#include "stat_cache.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>


/* on linux 2.4.29 + debian/ubuntu we have crashes if this is enabled */
#undef HAVE_POSIX_FADVISE
int sock, status, socklen;
struct sockaddr_in saddr;
struct ip_mreq imreq;

int file_handle_tmp; 
#define MAXBUFSIZE 65536

typedef struct multi_handle_
{
	char *buffer;
	int used;
	int size; 
	int cur_off;

}multi_handle_t;

static int flag = 0;
multi_handle_t *multi_handler = NULL;

multi_handle_t*  multicast_init()
{

	multi_handle_t *handle = malloc(sizeof(multi_handle_t));
	handle->size = 1024*1024;
	handle->buffer = malloc(handle->size);
	handle->used = 0;
	handle->cur_off = 0;

  // set content of struct saddr and imreq to zero
     memset(&saddr, 0, sizeof(struct sockaddr_in));
     memset(&imreq, 0, sizeof(struct ip_mreq));

  if((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
	assert(0);

	// me: debugging
	printf("[Debug] %s, %d \n", __FILE__, __LINE__);
	
saddr.sin_family = PF_INET;
       saddr.sin_port = htons(1234); // listen on port 4096
       saddr.sin_addr.s_addr = htonl(INADDR_ANY); // bind socket to any interface
       int status = bind(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

       if ( status < 0 )
       {
             printf("open socket error!");
		assert(0);
          }	

	// me: debugging
	printf("[Debug] %s, %d \n", __FILE__, __LINE__);
 	
	imreq.imr_multiaddr.s_addr = inet_addr("225.0.0.2");
       imreq.imr_interface.s_addr = INADDR_ANY; // use DEFAULT interface

       status = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                  (const void *)&imreq, sizeof(struct ip_mreq));

	// me: debugging
	printf("[Debug] %s, %d \n", __FILE__, __LINE__);

       int socklen = sizeof(struct sockaddr_in);
	flag = 1;

	return handle; }

int multicast_read(multi_handle_t *_handle, char *buffer, int len, int *offset)
{
#if 1
	{

	lseek(file_handle_tmp, *offset, SEEK_SET);
	int status = read(file_handle_tmp,buffer, len);
	
	return status;

	printf("[Debug] read status: previous offset: %d,  offset: %d status:  %d \n", _handle->cur_off,  *offset, status);
	if (_handle->cur_off > *offset)
		printf("[Debug] read status: ERROR \n");
	_handle->cur_off = *offset; 
	return status;
	}
	assert(len < _handle->size);

	printf("[Debug] read status: previous offset: %d,  offset: %d status:  %d \n", _handle->cur_off,  *offset, status);
	if (*offset > _handle->cur_off + _handle->used )
{	
		printf("[Debug] read status: ERROR \n");
		_handle->cur_off = *offset;
	}else if (*offset < _handle->cur_off)
	{
		_handle->cur_off = *offset;
		printf("[Debug] read status: ERROR \n");

}
	else
{
	int consume = *offset -  _handle->cur_off;
//	assert(_handle->cur_off + consume == *offset);
	// discard some data 	
	memcpy(_handle->buffer, _handle->buffer + consume, _handle->used - consume); 
	_handle->cur_off = *offset;
	_handle->used = _handle->used - consume; 
}
	// me: debugging
#endif
	while(len >= _handle->used)
	{ // receive packet from socket
#if 0
	   int status = recvfrom(sock,  _handle->buffer + _handle->used, MAXBUFSIZE, 0,
                     (struct sockaddr *)&saddr, &socklen);
#else  // for testing 
	
	lseek(file_handle_tmp, *offset, SEEK_SET);
	status = read(file_handle_tmp, _handle->buffer + _handle->used, len);
	//_handle->used = rc;
#endif 
	// me: debugging
	//printf("[Debug] %s, %d, used: %d offset: %d, len: %d, real read: %d \n", __FUNCTION__, __LINE__, _handle->used, *offset, len, status);
		if (status == -1)
		{
			printf("[Debug] Error when reading ...\n");
			assert(0);
			return -1;
		}else if (status == 0)
		{
			printf("[Debug] Error when reading ...\n");
			assert(0);
			return 0;
	}
		 	
		_handle->used += status;
    	};	
	
	// me: debugging
//	printf("[Debug] %s, %d \n", __FUNCTION__, __LINE__);
	memcpy(buffer, _handle->buffer, len);
	//assert(buffer[0] == 0x47);
	_handle->used = _handle->used - len;
	assert(_handle->used >= 0);
	memcpy(_handle->buffer, _handle->buffer + len , _handle->used);
	return len;
}


typedef struct mychunk_{
char *buff;
int used;
int size;
}mychunk_t;

mychunk_t *chunk_handle = NULL; 
mychunk_t * _mychunk_init()
{
	mychunk_t *handle = malloc(sizeof(mychunk_t));
	handle->size = 1024*1024;
	handle->used  = 0;
	handle->buff = malloc(handle->size);
	return handle;
}


FILE *file_out1 = NULL;

// me: add for debugging 
int send_file_to_socket(int file_fd, int sock_fd, int *offset, int len)
{
	int rc;
	if (chunk_handle == NULL)
		chunk_handle = _mychunk_init();

	if (file_out1 == NULL)
	{
                file_out1 = fopen("/home/huyle/tmp/out.ts", "wb");
		assert(file_out1 != NULL);
		}
	// me: debugging
	printf("[Debug] %s, %d \n", __FILE__, __LINE__);
	
	int remaining_len = len;
	const static max_len = 1024*256;	
//	while (remaining_len > 0)
	{


#if 0
	lseek(file_fd, *offset, SEEK_SET);
	rc = read(file_fd, chunk_handle->buff, len);
	chunk_handle->used = rc;
#else
	file_handle_tmp = file_fd; 
//	if (chunk_handle->used < len)
	{
		rc = multicast_read(multi_handler, chunk_handle->buff, len, offset);
                if(rc != len)
		{
                        printf("[Debug]  offset: %d, len: %d, actual read: %d \n", offset, len, rc);
			assert(0);
			return -1;
		}
		chunk_handle->used = rc;
	}	
#endif
                rc = write(sock_fd, chunk_handle->buff , rc);
		if (rc == -1)
		{
			return -1;
			assert(0);
		}
		else if (rc != chunk_handle->used)
		{
			printf("[Debug] warning %s, %d offset  can not write full (request: %d, written: %d)  \n", __FUNCTION__, __LINE__, chunk_handle->used, rc);	
		}		
		if (file_out1 != NULL)
			fwrite(chunk_handle->buff, 1, rc, file_out1);

		chunk_handle->used -= rc;
		assert(chunk_handle->used >= 0);	
		memcpy(chunk_handle->buff, chunk_handle->buff + rc, chunk_handle->used);
	}
	
	*offset = *offset + rc;
	return rc;
}


FILE *file_out = NULL;
int new_fd = 0;
int offset_end = 0;

int network_write_chunkqueue_linuxsendfile(server *srv, connection *con, int fd, chunkqueue *cq, off_t max_bytes) {
	chunk *c;


        int count_chunk = 0;
        for(c = cq->first;  (NULL != c); c = c->next)
        {
            count_chunk++;

        }

        printf("[Debug] %s, %d count chunk: %d \n", __FILE__, __LINE__, count_chunk);



	for(c = cq->first; (max_bytes > 0) && (NULL != c); c = c->next) {
		int chunk_finished = 0;

		switch(c->type) {
		case MEM_CHUNK: {

						// me: debugging
        printf("[Debug] %s, %d \n", __FILE__, __LINE__);
						
			char * offset;
			off_t toSend;
			ssize_t r;

			size_t num_chunks, i;
			struct iovec chunks[UIO_MAXIOV];
			chunk *tc;
			size_t num_bytes = 0;

			/* build writev list
			 *
			 * 1. limit: num_chunks < UIO_MAXIOV
			 * 2. limit: num_bytes < max_bytes
			 */
			for (num_chunks = 0, tc = c;
			     tc && tc->type == MEM_CHUNK && num_chunks < UIO_MAXIOV;
			     tc = tc->next, num_chunks++);

			for (tc = c, i = 0; i < num_chunks; tc = tc->next, i++) {
				if (tc->mem->used == 0) {
					chunks[i].iov_base = tc->mem->ptr;
					chunks[i].iov_len  = 0;
				} else {
					offset = tc->mem->ptr + tc->offset;
					toSend = tc->mem->used - 1 - tc->offset;

					chunks[i].iov_base = offset;

					/* protect the return value of writev() */
					if (toSend > max_bytes ||
					    (off_t) num_bytes + toSend > max_bytes) {
						chunks[i].iov_len = max_bytes - num_bytes;

						num_chunks = i + 1;
						break;
					} else {
						chunks[i].iov_len = toSend;
					}

					num_bytes += toSend;
				}
			}

                        // debug
                        char tmp_buff[1024*2];
                        printf("[Debug] %s, %d , num chunk: %d \n", __FILE__, __LINE__, num_chunks);
                        for (int j = 0; j < num_chunks; j++)
                        {
                            printf("[Debug] %s, %d , iov len: %d \n", __FILE__, __LINE__, chunks[j].iov_len);
                            memcpy(tmp_buff, chunks[j].iov_base, chunks[j].iov_len);
                            tmp_buff[chunks[j].iov_len] = NULL;

                            printf("[Debug] %s, %d , \n response header: %s \n", __FILE__, __LINE__, tmp_buff);


                        }

			if ((r = writev(fd, chunks, num_chunks)) < 0) {
				switch (errno) {
				case EAGAIN:
				case EINTR:
					r = 0;
					break;
				case EPIPE:
				case ECONNRESET:
					return -2;
				default:
					log_error_write(srv, __FILE__, __LINE__, "ssd",
							"writev failed:", strerror(errno), fd);

					return -1;
				}
			}

			/* check which chunks have been written */
			cq->bytes_out += r;
			max_bytes -= r;

			for(i = 0, tc = c; i < num_chunks; i++, tc = tc->next) {
				if (r >= (ssize_t)chunks[i].iov_len) {
					/* written */
					r -= chunks[i].iov_len;
					tc->offset += chunks[i].iov_len;

					if (chunk_finished) {
						/* skip the chunks from further touches */
						c = c->next;
					} else {
						/* chunks_written + c = c->next is done in the for()*/
						chunk_finished = 1;
					}
				} else {
					/* partially written */

					tc->offset += r;
					chunk_finished = 0;

					break;
				}
			}

			break;
		}
		case FILE_CHUNK: {

			ssize_t r;
			off_t offset;
			off_t toSend;
			stat_cache_entry *sce = NULL;

                        offset = c->file.start + c->offset;
			toSend = c->file.length - c->offset;
			if (toSend > max_bytes) toSend = max_bytes;

			/* open file if not already opened */
			if (-1 == c->file.fd) {
				//me: modify for debugging 

				if (-1 == (c->file.fd = open(c->file.name->ptr, O_RDONLY))) {
				//if (-1 == (c->file.fd = open("/var/www/html/cnn.small.ts", O_RDONLY))) {
					log_error_write(srv, __FILE__, __LINE__, "ss", "open failed: ", strerror(errno));

					return -1;
				}
                                printf("[Debug] open file %s, %d file name: %s, fid: %d \n", __FILE__, __LINE__, c->file.name->ptr, c->file.fd);

#ifdef FD_CLOEXEC
				fcntl(c->file.fd, F_SETFD, FD_CLOEXEC);
#endif
#ifdef HAVE_POSIX_FADVISE
				/* tell the kernel that we want to stream the file */
				if (-1 == posix_fadvise(c->file.fd, 0, 0, POSIX_FADV_SEQUENTIAL)) {
					if (ENOSYS != errno) {
						log_error_write(srv, __FILE__, __LINE__, "ssd",
							"posix_fadvise failed:", strerror(errno), c->file.fd);
					}
				}
#endif
			}
	


#if 1
			static int offset_1 = 0;
			if (offset == 0)
{			
			offset_1 = 0;
}
			int pre_offset_1 = offset_1;


	
                        printf("[Debug] %s, %d previous offset: %d, new offset: %d , F id: %d len: %d \n", __FILE__, __LINE__,  pre_offset_1, offset, c->file.fd, c->file.length);


#if 1


                            if (-1 == (r = sendfile(fd, c->file.fd, &offset, toSend))) {
#else

#if 0
                        if (offset == 0 || offset == 1618044)
                        {
                            new_fd = open("/var/www/html/axn.ts", O_RDONLY);
                            assert(new_fd != -1);
                        }
#else
                        new_fd = c->file.fd;
#endif
                        int read_fd = 0;
                        int *read_offset = 0;



                        if (HANDLER_ERROR == stat_cache_get_entry(srv, con, c->file.name, &sce)) {
                                /* file is gone ? */
                                assert(0);
                                return -1;
                        }

                        int offset_e = sce->st.st_size - 4022144;
                        printf("[Debug] %s, %d offset end: %d \n", __FILE__, __LINE__, offset_e);






                        if (offset >=  offset_e)
                        {
                            //off_t offset1 = offset - 58890552 + (15000000/188)*188;
                            //off_t offset1 = offset - 27434204 + (15000000/188)*188;
                           // off_t offset1 = offset - 1505882560 + (15000000/188)*188;

                            //assert(offset1 >= 0);
                            //off_t offset2 = offset1;



                            offset = offset - offset_e + 100*1024*1024;

                            read_fd = c->file.fd;
                            //offset = offset - 188;

                            r = sendfile(fd, read_fd, &offset, toSend);
                            offset += offset_e;

                          //  offset = offset1;
                           // *read_offset = offset;
                          //  offset = offset + (offset1 -offset2);
                          //  if (new_fd != 0)
                           // {
                            //    close(new_fd);
                             //   new_fd = 0;
                           // }

                        } else
                        {
                            read_fd = new_fd;
                            r = sendfile(fd, read_fd, &offset, toSend);
                            printf("[Debug] sending file %s, %d offset: %d, offset_1: %d, gap: %d  len: %d, writen: %d (%d, %d) read id: %d \n", __FILE__, __LINE__ , offset, offset_1, offset - offset_1, toSend, r, c->file.length, c->offset, read_fd);
                           // *read_offset = offset_1;
                        }



                        printf("[Debug] sending file %s, %d offset: %d, offset_1: %d, gap: %d  len: %d, writen: %d (%d, %d) read id: %d \n", __FILE__, __LINE__ , offset, offset_1, offset - offset_1, toSend, r, c->file.length, c->offset, read_fd);

                        offset_1 = offset;
                        if (-1 == r) {

                           // assert(0);

#endif

#else
			if (multi_handler == NULL)
				multi_handler = multicast_init();

			static int offset_1 = 0;
			if (offset == 0)
{			
			offset_1 = 0;
}
			int pre_offset_1 = offset_1;

			if (-1 == (r = send_file_to_socket(c->file.fd, fd, &offset_1, toSend))) {
#endif
                            printf("[Debug] %s, %d  ECONNRESET \n", __FILE__, __LINE__);

				switch (errno) {
				case EAGAIN:
				case EINTR:
					/* ok, we can't send more, let's try later again */
					r = 0;
					break;
				case EPIPE:
				case ECONNRESET:
					return -2;
				default:
					log_error_write(srv, __FILE__, __LINE__, "ssd",
							"sendfile failed:", strerror(errno), fd);
					return -1;
				}
			} else if (r == 0) {

                            printf("[Debug] %s, %d  remote network closed or file shrinked \n", __FILE__, __LINE__);

                           // assert(0);
				int oerrno = errno;
				/* We got an event to write but we wrote nothing
				 *
				 * - the file shrinked -> error
				 * - the remote side closed inbetween -> remote-close */

				if (HANDLER_ERROR == stat_cache_get_entry(srv, con, c->file.name, &sce)) {
					/* file is gone ? */
					assert(0);
					return -1;
				}

				if (offset > sce->st.st_size) {
					/* file shrinked, close the connection */
					errno = oerrno;
                                        //assert(0);
					return -1;
				}

				errno = oerrno;
				return -2;
			}


#if 0	
	printf("[Debug] %s, %d \n", __FILE__, __LINE__);	
	printf("[Debug] %s, %d \n", __FILE__, __LINE__);	
	FILE *file_in = NULL;
	printf("[Debug] %s, %d \n", __FILE__, __LINE__);	
	if (file_in == NULL)
	{
	file_in = fopen("/var/www/html/channel2.ts", "rb"); 
}
if (file_out == NULL)
{
	printf("[Debug] %s, %d \n", __FILE__, __LINE__);	
	file_out = fopen("/home/huyle/tmp/out.ts", "wb");
		assert(file_out != NULL);

}
		if (file_out != NULL)
{
	printf("[Debug] previous offset: %d, new offset: %d \n", pre_offset_1, offset_1);
	char *buffer = malloc(offset_1 - pre_offset_1 + 100);
	fseek(file_in, pre_offset_1, SEEK_SET);
	fread(buffer, 1, offset_1 - pre_offset_1, file_in);
	fwrite(buffer, 1, offset_1 - pre_offset_1, file_out);
	free(buffer);
	fseek(file_in, offset_1, SEEK_SET);
	fclose(file_in);
	}
#endif

#ifdef HAVE_POSIX_FADVISE
#if 0
#define K * 1024
#define M * 1024 K
#define READ_AHEAD 4 M
			/* check if we need a new chunk */
			if ((c->offset & ~(READ_AHEAD - 1)) != ((c->offset + r) & ~(READ_AHEAD - 1))) {
				/* tell the kernel that we want to stream the file */
				if (-1 == posix_fadvise(c->file.fd, (c->offset + r) & ~(READ_AHEAD - 1), READ_AHEAD, POSIX_FADV_NOREUSE)) {
					log_error_write(srv, __FILE__, __LINE__, "ssd",
						"posix_fadvise failed:", strerror(errno), c->file.fd);
				}
			}
#endif
#endif

			c->offset += r;
			cq->bytes_out += r;
			max_bytes -= r;

			if (c->offset == c->file.length) {
				chunk_finished = 1;
printf("[Debug] %s, %d \n", __FILE__, __LINE__);
				/* chunk_free() / chunk_reset() will cleanup for us but it is a ok to be faster :) */

				if (c->file.fd != -1) {

                                        printf("[Debug] %s, %d Close file: %s, file id: %d \n", __FILE__, __LINE__, c->file.name->ptr,  c->file.fd);
					close(c->file.fd);
					c->file.fd = -1;
				}
			}

			break;
		}
		default:

			log_error_write(srv, __FILE__, __LINE__, "ds", c, "type not known");

			return -1;
		}

		if (!chunk_finished) {
			/* not finished yet */

			break;
		}
	}

	return 0;
}

#endif
#if 0
network_linuxsendfile_init(void) {
	p->write = network_linuxsendfile_write_chunkset;
}
#endif
