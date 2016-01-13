#ifndef BUFFER_HD

  #include <windows.h>

  #define BUFFER_HD



  /* maximum size for an ethernet packet  */
  /* 2048 bytes: this is plenty and it is */
  /* a "good number".                     */
  #define MAX_BUFF_SIZE 2048
  
  /* number of buffer */
  #define MAX_BUFF_NUM  400
  
  /* Calculate the next index in the buffer */
  #define NEXT_POS(i) ((i+1)%MAX_BUFF_NUM)
  
  /* define one buffer entry */
  struct S_Case {
                  int  size;
                  int  status;  /* FULL or EMPTY */
                  char buffer[MAX_BUFF_SIZE];
                };
  typedef struct S_Case Case;
  
  int      Init_Rolling();
  BOOLEAN  Close_Rolling();
  Case*    Get_Wr_Buffer();
  Case*    Get_Rd_Buffer();
  void     Next_Write();
  void     Next_Read();
  int      Get_Wr_Status();
  int      Set_Wr_Status(int);
  int      Get_Rd_Status();
  int      Set_Rd_Status(int);

  
#endif