#include<termios.h>
char getkey(){
 char ch;
 struct termios old_term;
 struct termios cur_term;
 int ret ;
 tcgetattr(STDIN_FILENO, &old_term);
 memcpy(&cur_term, &old_term, sizeof(cur_term));
 cur_term.c_lflag &= ~(ICANON);
 cur_term.c_cc[VMIN] = 1;
 cur_term.c_cc[VTIME] = 0;
 ret = tcsetattr(STDIN_FILENO, TCSANOW, &cur_term);
 if (ret < 0){
  printf("Can't set\n");
  return 1;
 }
 fflush(stdout);
 ret = read(STDIN_FILENO, &ch, 1);
 if (ret <= 0){
  printf("Error\n");
 }
 tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
 return(ch);
}


