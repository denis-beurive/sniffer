#include <stdio.h>

/* Renvoie la taille en octet d'un fichier deja ouvert en LECTURE*/
long int File_Length (FILE *fd) /* 100% ANSI */
{
        long int taille, courant;

        courant = ftell (fd);
        if (courant == -1) { return -1; }
        if (fseek (fd, 0, SEEK_END)) { return -1; }
        taille = ftell (fd);
        if (taille == -1) { return -1; }
        if (fseek (fd, courant, SEEK_SET)) { return -1; }

        return (taille);
}
