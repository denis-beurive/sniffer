#include <stdio.h>
#include "dump_body.h"

#define PRINTABLE         0
#define NON_PRINTABLE     1

#define HEXA              26 /* must be a multiple of 2 */
#define LINE_SIZE         80


/********************************************************/
/* char int_to_char (unsigned char)                     */
/*                                                      */
/* Return the hexa character associated with a decimal  */
/* value.                                               */
/*                                                      */
/* -> c: (in) decimal value.                            */
/********************************************************/

char int_to_char (unsigned char c)
{
  switch (c)
  {
    case 0:  return '0';
    case 1:  return '1';
    case 2:  return '2';
    case 3:  return '3';
    case 4:  return '4';
    case 5:  return '5';
    case 6:  return '6';
    case 7:  return '7';
    case 8:  return '8';
    case 9:  return '9';
    case 10: return 'A';
    case 11: return 'B';
    case 12: return 'C';
    case 13: return 'D';
    case 14: return 'E';
    case 15: return 'F';
  }

  return 0;
}

/********************************************************/
/* int print_char(char c): test if a charactere can be  */
/* printed.                                             */
/*                                                      */
/* - returns PRINTABLE if 'c' can be printed.           */
/* - returns NON_PRINTABLE if 'c' can't be printed      */
/*                                                      */
/* Note: there is a C macro to do that (isgraph). But   */
/* I have decided that I won't use it because I want    */
/* this code to be __100%_portable__.                   */
/********************************************************/

int print_char (char c)
{
  switch (c)
  {
     case ' ':   return PRINTABLE;
     case '!':   return PRINTABLE;
     case '\"':  return PRINTABLE;
     case '#':   return PRINTABLE;
     case '$':   return PRINTABLE;
     case '%':   return PRINTABLE;
     case '&':   return PRINTABLE;
     case '\'':  return PRINTABLE;
     case '(':   return PRINTABLE;
     case ')':   return PRINTABLE;
     case '*':   return PRINTABLE;
     case '+':   return PRINTABLE;
     case ',':   return PRINTABLE;
     case '-':   return PRINTABLE;
     case '.':   return PRINTABLE;
     case '/':   return PRINTABLE;
     case '0':   return PRINTABLE;
     case '1':   return PRINTABLE;
     case '2':   return PRINTABLE;
     case '3':   return PRINTABLE;
     case '4':   return PRINTABLE;
     case '5':   return PRINTABLE;
     case '6':   return PRINTABLE;
     case '7':   return PRINTABLE;
     case '8':   return PRINTABLE;
     case '9':   return PRINTABLE;
     case ':':   return PRINTABLE;
     case ';':   return PRINTABLE;
     case '<':   return PRINTABLE;
     case '=':   return PRINTABLE;
     case '>':   return PRINTABLE;
     case '?':   return PRINTABLE;
     case '@':   return PRINTABLE;
     case 'A':   return PRINTABLE;
     case 'B':   return PRINTABLE;
     case 'C':   return PRINTABLE;
     case 'D':   return PRINTABLE;
     case 'E':   return PRINTABLE;
     case 'F':   return PRINTABLE;
     case 'G':   return PRINTABLE;
     case 'H':   return PRINTABLE;
     case 'I':   return PRINTABLE;
     case 'J':   return PRINTABLE;
     case 'K':   return PRINTABLE;
     case 'L':   return PRINTABLE;
     case 'M':   return PRINTABLE;
     case 'N':   return PRINTABLE;
     case 'O':   return PRINTABLE;
     case 'P':   return PRINTABLE;
     case 'Q':   return PRINTABLE;
     case 'R':   return PRINTABLE;
     case 'S':   return PRINTABLE;
     case 'T':   return PRINTABLE;
     case 'U':   return PRINTABLE;
     case 'V':   return PRINTABLE;
     case 'W':   return PRINTABLE;
     case 'X':   return PRINTABLE;
     case 'Y':   return PRINTABLE;
     case 'Z':   return PRINTABLE;
     case '[':   return PRINTABLE;
     case '\\':  return PRINTABLE;
     case ']':   return PRINTABLE;
     case '^':   return PRINTABLE;
     case '_':   return PRINTABLE;
     case '`':   return PRINTABLE;
     case 'a':   return PRINTABLE;
     case 'b':   return PRINTABLE;
     case 'c':   return PRINTABLE;
     case 'd':   return PRINTABLE;
     case 'e':   return PRINTABLE;
     case 'f':   return PRINTABLE;
     case 'g':   return PRINTABLE;
     case 'h':   return PRINTABLE;
     case 'i':   return PRINTABLE;
     case 'j':   return PRINTABLE;
     case 'k':   return PRINTABLE;
     case 'l':   return PRINTABLE;
     case 'm':   return PRINTABLE;
     case 'n':   return PRINTABLE;
     case 'o':   return PRINTABLE;
     case 'p':   return PRINTABLE;
     case 'q':   return PRINTABLE;
     case 'r':   return PRINTABLE;
     case 's':   return PRINTABLE;
     case 't':   return PRINTABLE;
     case 'u':   return PRINTABLE;
     case 'v':   return PRINTABLE;
     case 'w':   return PRINTABLE;
     case 'x':   return PRINTABLE;
     case 'y':   return PRINTABLE;
     case 'z':   return PRINTABLE;
     case '{':   return PRINTABLE;
     case '|':   return PRINTABLE;
     case '}':   return PRINTABLE;
     case '~':   return PRINTABLE;
     default :   return NON_PRINTABLE;
  }
}

/********************************************************/
/*                          dump                        */
/*                                                      */
/* Print the content of a binary buffer as following:   */
/* hh hh hh hh hh hh hh ...     ccccccc...              */
/* hh hh hh hh hh hh hh ...     ccccccc...              */
/* hh hh hh hh hh hh hh ...     ccccccc...              */
/* ...                          ...                     */
/* Where: hh = hexadecomal number (1 byte)              */
/*        c  = printable character                      */
/*                                                      */
/* -> buff: (in) buffer that contains binary data.      */
/* -> size: (in) size of buffer (number of bytes to     */
/*               print.                                 */
/********************************************************/

void dump (char *buff, unsigned int size)
{
  char          line[LINE_SIZE];
  unsigned int  i, c, l, r, p;
  unsigned char dg;
  int           ascii;

  /* 1 byte => 2 hexa char */

  l     = size / (HEXA/2);       /* entire lines */
  r     = size - (l*(HEXA/2));   /* char left    */
  p     = 0;

  for (i=0; i<LINE_SIZE; i++) { line[i] = ' '; }
  fprintf (stdout, "\n\n");

  /* Printing entire lines */
  for (i=0; i<l; i++)
  {
    ascii = 0;
    for (c=0; c<(HEXA/2); c++)
    {
      dg = buff[p++];
      line[c*3+1] = int_to_char (dg & 0x0F);
      line[c*3+2] = int_to_char ((dg & 0xF0) >> 4);
      if (print_char(dg) == PRINTABLE)
      { line[(HEXA/2)*3+4+c] = dg; ascii = 1; }
      else
      { line[(HEXA/2)*3+4+c] = ' '; }
    }
    line[(HEXA/2)*4+4] = 0;
    fprintf (stdout, "%s", line);

    if (ascii == 1)
    { fprintf (stdout, " -a-"); }

    fprintf (stdout, "\n");
  }

  for (i=0; i<LINE_SIZE; i++) { line[i] = ' '; }

  /* printing left characters */
  ascii = 0;
  for (c=0; c<r; c++)
  {
    dg = buff[p++];
    line[c*3+1] = int_to_char (dg & 0x0F);
    line[c*3+2] = int_to_char (((dg & 0xF0) >> 4) & 0x0F);
    if (print_char(dg) == PRINTABLE)
    { line[(HEXA/2)*3+4+c] = dg; ascii = 1; }
    else
    { line[(HEXA/2)*3+4+c] = ' '; }
  }
  line[(HEXA/2)*3+4+r] = 0;
  fprintf (stdout, "%s", line);

  for (c=0; c<(HEXA/2)-r; c++) { fprintf (stdout, " "); }

  if (ascii == 1)
  { fprintf (stdout, " -a-"); }
  fprintf (stdout, "\n");
  
}

/********************************************************/
/*                      dump_ascii                      */
/*                                                      */
/* Dump the packet body in ascii.                       */
/*                                                      */
/* -> buff: (in) buffer that contains binary data.      */
/* -> size: (in) size of buffer (number of bytes to     */
/*               print.                                 */
/********************************************************/

void dump_ascii (char *buff, unsigned int size)
{
  char          *c;
  int           flag, n;
  unsigned int  i;

  c    = buff;
  flag = 0;

  fprintf (stdout, "\n--- Start of ASCII data ---\n");
  n=0;
  for (i=0; i<size; i++)
  {
    if (print_char(*c) == PRINTABLE)
    {
      fprintf (stdout, "%c", *c);
      flag = 0;
    }
    else
    {
      if (flag == 0)
      { fprintf (stdout, " "); flag = 1; }
    }
    c++;
    if (n == 70) { fprintf (stdout, "\n"); n=0; }
    else { n++; }
  }
  fprintf (stdout, "\n---  End of ASCII data  ---\n");
}

/********************************************************/
/*                       dump_hexa                      */
/*                                                      */
/* Dump the packet body in ascii.                       */
/*                                                      */
/* -> buff: (in) buffer that contains binary data.      */
/* -> size: (in) size of buffer (number of bytes to     */
/*               print.                                 */
/********************************************************/

void dump_hexa (char *buff, unsigned int size)
{
  char          line[LINE_SIZE];
  unsigned int  i, c, l, r, p;
  unsigned char dg;

  /* 1 byte => 2 hexa char */

  l     = size / (HEXA/2);       /* entire lines */
  r     = size - (l*(HEXA/2));   /* char left    */
  p     = 0;

  for (i=0; i<LINE_SIZE; i++) { line[i] = ' '; }
  fprintf (stdout, "\n\n");

  /* Printing entire lines */
  for (i=0; i<l; i++)
  {
    for (c=0; c<(HEXA/2); c++)
    {
      dg = buff[p++];
      line[c*3+1] = int_to_char (dg & 0x0F);
      line[c*3+2] = int_to_char ((dg & 0xF0) >> 4);
    }
    line[(HEXA/2)*4+4] = 0;
    fprintf (stdout, "%s\n", line);
  }

  for (i=0; i<LINE_SIZE; i++) { line[i] = ' '; }

  /* printing left characters */
  for (c=0; c<r; c++)
  {
    dg = buff[p++];
    line[c*3+1] = int_to_char (dg & 0x0F);
    line[c*3+2] = int_to_char (((dg & 0xF0) >> 4) & 0x0F);
  }
  line[(HEXA/2)*3+4+r] = 0;
  fprintf (stdout, "%s\n", line);
}



#ifdef TEST

int main (void)
{
  char  buff[256];
  int   i;
  
  for (i=0; i<256; i++) { buff[i] = (char)i; }
  dump (buff, 256);
  return 0;
}

#endif

