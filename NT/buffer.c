/* #include <winbase.h> */
#include "buffer.h"
#include "dump.h"

/******************************************************/
/*              Global/private variables              */
/******************************************************/

  /* Rolling buffer */
  static Case Rolling[MAX_BUFF_NUM];

  /* index used to write in the buffer */
  static int Write_Id;

  /* index used to read in the buffer */
  static int Read_Id;

/******************************************************/
/*          Semaphore for mutual exclusion            */
/******************************************************/

  /* To protect the status value (FULL or EMPTY) */
  HANDLE Mutex_On_Status;

/******************************************************/
/*            Initialize the rolling buffer           */
/*                                                    */
/* Return value:                                      */
/*    o PACKET_ROLL_OK:                               */
/*      Initialization OK.                            */
/*    o PACKET_ROLL_MUTEX_ERROR:                      */
/*      Can not create mutex.                         */
/******************************************************/

int Init_Rolling ()
{
  int i;
  
  /* Initialise buffers */

  Write_Id = 0;
  Read_Id  = 0;
  
  for (i=0; i<MAX_BUFF_NUM; i++)
  {
    (Rolling[i]).size        = 0;
    (Rolling[i]).status      = EMPTY;
    ((Rolling[i]).buffer)[0] = 0;
  }

  /* Create Mutex to protect the buffer status */ 

  Mutex_On_Status = CreateMutex
  (
    NULL,   /* address of security attributes. NULL => default attributes */
    FALSE,	/* flag for initial ownership. FALSE => not owned */
    NULL    /* address of mutex-object name. NULL => no name */
   );

  if (Mutex_On_Status == NULL) { return PACKET_ROLL_MUTEX_ERROR; }

  return PACKET_ROLL_OK;
}

/******************************************************/
/*               Close the rolling buffer             */
/*                                                    */
/* Return value:                                      */
/*   o TRUE:                                          */
/*     Rolling buffer successfuly closed.             */
/*   o FALSE:                                         */
/*     Error while closing mutex.                     */
/******************************************************/

BOOLEAN Close_Rolling ()
{
  return (CloseHandle (Mutex_On_Status));
}

/******************************************************/
/*      Return current buffer (to fill) address       */
/******************************************************/

Case* Get_Wr_Buffer()
{
  return &(Rolling[Write_Id]);
}

/******************************************************/
/*        Return current buffer to read address       */
/******************************************************/

Case* Get_Rd_Buffer()
{
  return &(Rolling[Read_Id]);
}

/******************************************************/
/*             Increment the Write index              */
/******************************************************/

void Next_Write ()
{
  Write_Id = NEXT_POS(Write_Id);
}

/******************************************************/
/*             Increment the Read index               */
/******************************************************/

void Next_Read ()
{
  Read_Id = NEXT_POS(Read_Id);
}

/******************************************************/
/*  Get the status (FULL/EMPTY) of the write buffer   */
/*                                                    */
/* Return value:                                      */
/*   o PACKET_ROLL_GET_MUTEX_ERROR: error while       */
/*     atempting to get the mutex.                    */
/*   o PACKET_ROLL_RELEASE_MUTEX_ERROR: error while   */
/*     atempting to release the mutex.                */
/******************************************************/

int Get_Wr_Status()
{
  int status;

  if ( 
       WaitForSingleObject
       (
         Mutex_On_Status,   /* handle of object to wait for */
         INFINITE 	        /* time-out interval in milliseconds */
       ) == WAIT_FAILED
     )
  { return PACKET_ROLL_GET_MUTEX_ERROR; }
  
  status = (Rolling[Write_Id]).status;
  
  if (ReleaseMutex (Mutex_On_Status) == FALSE)
  { return PACKET_ROLL_RELEASE_MUTEX_ERROR; }

  return status;
}

/******************************************************/
/*   Set the status (FULL/EMPTY) of the write buffer  */
/*                                                    */
/* Return value:                                      */
/*   o PACKET_ROLL_GET_MUTEX_ERROR: error while       */
/*     atempting to get the mutex.                    */
/*   o PACKET_ROLL_RELEASE_MUTEX_ERROR: error while   */
/*     atempting to release the mutex.                */
/******************************************************/

int Set_Wr_Status(int status)
{
  if ( 
       WaitForSingleObject
       (
         Mutex_On_Status,   /* handle of object to wait for */
         INFINITE 	        /* time-out interval in milliseconds */
       ) == WAIT_FAILED
     )
  { return PACKET_ROLL_GET_MUTEX_ERROR; }
  
  (Rolling[Write_Id]).status = status;
  
  if (ReleaseMutex (Mutex_On_Status) == FALSE)
  { return PACKET_ROLL_RELEASE_MUTEX_ERROR; }

  return PACKET_ROLL_OK;
}

/******************************************************/
/*   Get the status (FULL/EMPTY) of the read buffer   */
/*                                                    */
/* Return value:                                      */
/*   o PACKET_ROLL_GET_MUTEX_ERROR: error while       */
/*     atempting to get the mutex.                    */
/*   o PACKET_ROLL_RELEASE_MUTEX_ERROR: error while   */
/*     atempting to release the mutex.                */
/******************************************************/

int Get_Rd_Status()
{
  int status;

  if ( 
       WaitForSingleObject
       (
         Mutex_On_Status,   /* handle of object to wait for */
         INFINITE 	        /* time-out interval in milliseconds */
       ) == WAIT_FAILED
     )
  { return PACKET_ROLL_GET_MUTEX_ERROR; }
  
  status = (Rolling[Read_Id]).status;
  
  if (ReleaseMutex (Mutex_On_Status) == FALSE)
  { return PACKET_ROLL_RELEASE_MUTEX_ERROR; }

  return status;
}

/******************************************************/
/*    Set the status (FULL/EMPTY) of the read buffer  */
/*                                                    */
/* Return value:                                      */
/*   o PACKET_ROLL_GET_MUTEX_ERROR: error while       */
/*     atempting to get the mutex.                    */
/*   o PACKET_ROLL_RELEASE_MUTEX_ERROR: error while   */
/*     atempting to release the mutex.                */
/******************************************************/

int Set_Rd_Status(int status)
{
  if ( 
       WaitForSingleObject
       (
         Mutex_On_Status,   /* handle of object to wait for */
         INFINITE 	        /* time-out interval in milliseconds */
       ) == WAIT_FAILED
     )
  { return PACKET_ROLL_GET_MUTEX_ERROR; }
  
  (Rolling[Read_Id]).status = status;
  
  if (ReleaseMutex (Mutex_On_Status) == FALSE)
  { return PACKET_ROLL_RELEASE_MUTEX_ERROR; }

  return PACKET_ROLL_OK;
}
