#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <re2/re2.h>
#include <re2/stringpiece.h>
#include <limits.h>

using namespace std;
using namespace re2;

typedef unsigned char   UCHAR;
typedef unsigned char *UCHARP;

void grep(char *regexp, int fd, char *name);
void matcher(RE2 &re, UCHARP beg, UCHARP end);
UCHARP get_line_beg(UCHARP p, UCHARP beg);

void usage(void) {
  fprintf(stderr, "usage: grep (regexp|-f regexp-file) file+");
  exit(1);
}

int main(int argc, char* argv[]) {
  int opt, i, fd;

  char buf[1<<14], *regexp = NULL;

  if (argc < 3) {
    usage();
  } else {
    while ((opt=getopt(argc, argv, "f:")) != -1) {
      switch (opt) {
      case 'f':
        {
          FILE *fp = fopen(optarg, "r");
          fgets(buf, sizeof(buf), fp);
          regexp = buf;
          fclose(fp);
          optind--;
        }
        break;
      default: usage();
      }
    }

    if (regexp == NULL) {
      if (optind > argc) {
        usage();
      }
     regexp = argv[optind];
    }

    for (i = optind+1; i < argc; i++) {
      fd = open(argv[i], O_RDONLY, 0666);
      if (fd == 0) {
        fprintf(stderr, "can't open %s:", argv[i]);
        continue;
      }
      grep(regexp, fd, argc > 3 ? argv[i] : NULL);
      close(fd);
    }
  }

  return 0;
}

void grep(char *regexp, int fd, char *name) {
  caddr_t file_mmap;
  UCHARP end, beg;
  off_t size;
  struct stat sb;

  if (fstat(fd, &sb)) {
    fprintf(stderr, "can't fstat %s\n", name);
    exit(0);
  }

  size = sb.st_size;
  file_mmap = (caddr_t)mmap(NULL, size, PROT_READ, MAP_SHARED, fd, (off_t)0);

  if (file_mmap == (caddr_t)-1) {
    fprintf(stderr, "can't mmap %s\n", name);
    exit(0);
  }

  beg = (UCHARP) file_mmap;
  end = beg + size - 1;

  string regex = regexp;

  RE2::Options options;
  options.set_dot_nl(true);
  options.set_utf8(false);
  options.set_max_mem(64<<20);
  options.set_log_errors(false);

  RE2 re(regex, options);
  re.ok();

  matcher(re, beg, end);

  munmap(file_mmap, size);
  return;
}

void matcher(RE2 &re, UCHARP beg, UCHARP end) {
  string contents = string((const char *)beg, (end - beg));
  StringPiece input(contents);
  int i, margc=re.NumberOfCapturingGroups();
  StringPiece word[margc];
  RE2::Arg margv[margc];
  RE2::Arg * margs[margc];
  const map<int, string>& namedmap = re.CapturingGroupNames();
  std::map<int, string>::const_iterator it;
  long start=(long) input.data();
  for (i = 0; i < margc; i++) {
    margv[i] = &word[i];
    margs[i] = &margv[i];
  }
  while (RE2::FindAndConsumeN(&input, re, margs, margc)) {
    for (int i = 0; i < margc; i++) {
      if(word[i].size()==0) continue;
      it=namedmap.find(i+1);
      if(it!=namedmap.end()) {
        cout << it->second << "\t";
      } else {
        cout << i << "\t";
      }
      cout << ((long) word[i].data()) - start;
      cout << "\t" << (long) (word[i].size()) << endl;
    }
  }
  return;
}
