#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#include <spawn.h>
#include <sys/wait.h>
#include <mach/mach.h>

int main(int argc, char **argv, char **envp) {
	if (argc < 2) {
		printf("Expected same <program>\n");
		return 1;
	}

	char my_path[PATH_MAX+1];
	if (getcwd(my_path, sizeof(my_path)) == NULL) {
		printf("Failed to get path of same\n");
		return 1;
	}
	printf("my path: %s\n", my_path);

	char *program_name = argv[1];

	pid_t child_pid;
	char **my_argv = argv + 1;

	int env_len = 1;
	char **environ = envp;
	while (*environ) {
		env_len++;
		environ++;
	}

	char **envs = calloc(sizeof(char *), env_len + 1);
	int path_buffer_size = PATH_MAX + 1025;
	char *path_buffer = calloc(path_buffer_size, 1);
	snprintf(path_buffer, path_buffer_size, "DYLD_INSERT_LIBRARIES=%s/%s", my_path, "same.dylib");

	for (int i = 0; i < env_len; i++) {
		envs[i] = envp[i];
	}
	envs[env_len - 1] = path_buffer;

	int status = posix_spawn(&child_pid, program_name, NULL, NULL, my_argv, envs);
	if (status == 0) {
		printf("Child pid: %i\n", child_pid);
		do {
/*
			mach_port_t me = mach_task_self();
			mach_port_t task;
			kern_return_t ret = task_for_pid(me, child_pid, &task);
			if (ret != KERN_SUCCESS) {
				printf("task_for_pid failed: %s\n", mach_error_string(ret));
				return 1;
			}
*/

			if (waitpid(child_pid, &status, 0) != -1) {
				printf("Child status: %d\n", WEXITSTATUS(status));
			} else {
				perror("waitpid");
				return 1;
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	} else {
		printf("posix_spawn: %s\n", strerror(status));
	}

	return 0;
}
