#include <string.h>
#include <stdio.h>
#include "getopt.h"

char *optarg = NULL;
int optind = 1;
int opterr = 1;
int optopt = 0;

static char *nextchar = NULL;

int getopt(int argc, char *const argv[], const char *optstring)
{
    if (optind >= argc || argv[optind] == NULL || argv[optind][0] != '-' || argv[optind][1] == '\0')
        return -1;

    if (strcmp(argv[optind], "--") == 0)
    {
        optind++;
        return -1;
    }

    if (nextchar == NULL || *nextchar == '\0')
        nextchar = argv[optind] + 1;

    char c = *nextchar++;
    const char *temp = strchr(optstring, c);

    if (temp == NULL || c == ':')
    {
        optopt = c;
        if (opterr && *optstring != ':')
            fprintf(stderr, "%s: invalid option -- %c\n", argv[0], c);
        if (*nextchar == '\0')
        {
            optind++;
            nextchar = NULL;
        }
        return '?';
    }

    if (temp[1] == ':')
    {
        if (*nextchar != '\0')
        {
            optarg = nextchar;
            optind++;
            nextchar = NULL;
        }
        else if (optind + 1 < argc)
        {
            optarg = argv[optind + 1];
            optind += 2;
            nextchar = NULL;
        }
        else
        {
            optopt = c;
            if (opterr && *optstring != ':')
                fprintf(stderr, "%s: option requires an argument -- %c\n", argv[0], c);
            optind++;
            nextchar = NULL;
            return (optstring[0] == ':') ? ':' : '?';
        }
    }
    else
    {
        if (*nextchar == '\0')
        {
            optind++;
            nextchar = NULL;
        }
    }

    return c;
}

int getopt_long(int argc, char *const argv[], const char *optstring, const struct option *longopts, int *longindex)
{
    if (optind >= argc || argv[optind] == NULL || argv[optind][0] != '-')
        return -1;

    if (strcmp(argv[optind], "--") == 0)
    {
        optind++;
        return -1;
    }

    if (argv[optind][0] == '-' && argv[optind][1] == '-')
    {
        const char *name = argv[optind] + 2;
        const char *equals = strchr(name, '=');
        size_t namelen = equals ? (size_t)(equals - name) : strlen(name);

        for (int i = 0; longopts[i].name != NULL; i++)
        {
            if (strncmp(name, longopts[i].name, namelen) == 0 && strlen(longopts[i].name) == namelen)
            {
                if (longindex)
                    *longindex = i;

                optind++;

                if (longopts[i].has_arg == required_argument || longopts[i].has_arg == optional_argument)
                {
                    if (equals)
                    {
                        optarg = (char *)(equals + 1);
                    }
                    else if (longopts[i].has_arg == required_argument)
                    {
                        if (optind < argc)
                        {
                            optarg = argv[optind];
                            optind++;
                        }
                        else
                        {
                            if (opterr)
                                fprintf(stderr, "%s: option '--%s' requires an argument\n", argv[0], longopts[i].name);
                            return '?';
                        }
                    }
                }

                if (longopts[i].flag)
                {
                    *longopts[i].flag = longopts[i].val;
                    return 0;
                }
                return longopts[i].val;
            }
        }

        if (opterr)
            fprintf(stderr, "%s: unrecognized option '--%s'\n", argv[0], name);
        optind++;
        return '?';
    }

    return getopt(argc, argv, optstring);
}
