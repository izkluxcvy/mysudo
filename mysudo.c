#define _DEFAULT_SOURCE
#include <crypt.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#define AUTHORIZED_USER "user"

static void auth_user(char *username) {
    if (strcmp(username, AUTHORIZED_USER)) {
        fprintf(stderr, "Unauthorized user\n");
        exit(1);
    }
}

static void read_challenge(char *challenge, size_t size) {
    struct termios old_term, new_term;

    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    printf("Password: ");
    fflush(stdout);

    if (!fgets(challenge, size, stdin)) {
        fprintf(stderr, "Failed to read password\n");
        exit(1);
    }

    challenge[strcspn(challenge, "\n")] = 0;

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    printf("\n");
}

static void auth_password(const struct passwd *pw) {
    char challenge[256];
    read_challenge(challenge, sizeof(challenge));

    struct spwd *spw = getspnam(pw->pw_name);
    if (!spw) {
        fprintf(stderr, "Failed to get shadow password\n");
        exit(1);
    }

    char *hashed = crypt(challenge, spw->sp_pwdp);
    if (!hashed) {
        fprintf(stderr, "Failed to hash password\n");
        exit(1);
    }

    // memset_explicit(challenge, 0, sizeof(challenge));
    explicit_bzero(challenge, sizeof(challenge));

    if (strcmp(hashed, spw->sp_pwdp)) {
        fprintf(stderr, "Authentication failed\n");
        exit(1);
    }
}

static void auth() {
    uid_t          uid = getuid();
    struct passwd *pw  = getpwuid(uid);
    if (!pw) {
        fprintf(stderr, "Failed to get user\n");
        exit(1);
    }

    auth_user(pw->pw_name);
    auth_password(pw);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command>\n", argv[0]);
        return 1;
    }

    auth();

    execvp(argv[1], &argv[1]);
}
