#include "pwd_drv.h"
#include <stdio.h>
#include <string.h>

#include <assert.h>

static ErlDrvEntry driver_entry__ = {
  NULL,                             /* init */
  start,                            /* startup (defined below) */
  stop,                             /* shutdown (defined below) */
  NULL,                             /* output */
  NULL,                             /* ready_input */
  NULL,                             /* ready_output */
  "pwd_drv",                        /* the name of the driver */
  NULL,                             /* finish */
  NULL,                             /* handle */
  control,                          /* control */
  NULL,                             /* timeout */
  NULL,                             /* outputv (defined below) */
  NULL,                             /* ready_async */
  NULL,                             /* flush */
  NULL,                             /* call */
  NULL,                             /* event */
  ERL_DRV_EXTENDED_MARKER,          /* ERL_DRV_EXTENDED_MARKER */
  ERL_DRV_EXTENDED_MAJOR_VERSION,   /* ERL_DRV_EXTENDED_MAJOR_VERSION */
  ERL_DRV_EXTENDED_MINOR_VERSION,   /* ERL_DRV_EXTENDED_MINOR_VERSION */
  ERL_DRV_FLAG_USE_PORT_LOCKING,    /* ERL_DRV_FLAGs */
  NULL,                             /* handle2 */
  NULL,                             /* process_exit */
  NULL,                             /* stop_select */
  NULL                              /* emergency_close */
};

static size_t group_mem_length (struct group * grp);

DRIVER_INIT (pwd_driver)
{
  return &driver_entry__;
}

static ErlDrvData
start (ErlDrvPort port, char *cmd)
{
  FILE *log = fopen ("/tmp/erlang-pwd-drv.log", "a+");
  if (!log)
    {
      fprintf (stderr, "Couldn't create log file\n");
      fflush (stderr);
      return (ErlDrvData) -1;
    }

  pwd_drv_t *drv = (pwd_drv_t *)driver_alloc (sizeof (pwd_drv_t));
  if (!drv)
    {
      fprintf (log, "Couldn't allocate memory for driver\n");
      fflush (log);
      fclose (log);

      return (ErlDrvData) -1;
    }

  drv->port = port;
  drv->log  = log;

  fprintf (drv->log, "Start pwd driver\n");
  fflush (drv->log);

  return (ErlDrvData) drv;
}

static void
stop (ErlDrvData p)
{
  pwd_drv_t *drv = (pwd_drv_t *)p;


  fprintf (drv->log, "Stop pwd driver\n");
  fflush (drv->log);
  fclose (drv->log);

  drv->log = 0;

  driver_free (drv);
}

ErlDrvSSizeT
control (ErlDrvData p,
         unsigned int command,
         char *buf,
         ErlDrvSizeT len,
         char **rbuf,
         ErlDrvSizeT rlen)
{
  pwd_drv_t *drv = (pwd_drv_t *)p;
  if (len)
    buf[len] = 0;

  switch (command)
    {
    case CMD_GET_PWUID:
      get_pwuid (drv, buf);
      break;
    case CMD_GET_PWNAM:
      get_pwnam (drv, buf);
      break;
    case CMD_GET_PWALL:
      get_pwall (drv);
      break;
    case CMD_GET_GRGID:
      get_grgid (drv, buf);
      break;
    case CMD_GET_GRNAM:
      get_grnam (drv, buf);
      break;
    case CMD_GET_GRALL:
      get_grall (drv);
      break;
    default:
      send_error (drv, "error", "unknown_command");
      break;
    }

  return 0;
}

static int 
send_error (pwd_drv_t *drv, 
            char *tag,
            char *msg)
{
  ErlDrvTermData spec[] = {
      ERL_DRV_ATOM, driver_mk_atom (tag),
      ERL_DRV_STRING, (ErlDrvTermData)msg, strlen (msg),
      ERL_DRV_TUPLE, 2
  };

  return erl_drv_output_term (driver_mk_port(drv->port),
                              spec,
                              sizeof (spec) / sizeof (spec[0]));
}

static int
get_pwuid (pwd_drv_t *drv, char *cmd)
{
  __uid_t uid = atoi (cmd);
  struct passwd *pwd = getpwuid (uid);
  if (!pwd)
    {
      fprintf (drv->log, "getpwuid returns NULL for %s\n", cmd);
      fflush (drv->log);

      return send_error (drv, "error", "unknown_uid");
    }

  size_t result_count = 0;
  ErlDrvTermData *result = make_passwd (drv, pwd, &result_count);
  if (!result)
    {
      return send_error (drv, "error", "Couldn't allocate memory");
    }

  int r = erl_drv_output_term (driver_mk_port(drv->port),
                               result,
                               result_count);

  driver_free (result);
  return r;
}

static int
get_pwnam (pwd_drv_t *drv, char *cmd)
{
  struct passwd *pwd = getpwnam (cmd);
  if (!pwd)
    {
      fprintf (drv->log, "getpwnam returns NULL for %s\n", cmd);
      fflush (drv->log);

      return send_error (drv, "error", "unknown_name");
    }

  size_t result_count = 0;
  ErlDrvTermData *result = make_passwd (drv, pwd, &result_count);
  if (!result)
    {
      return send_error (drv, "error", "Couldn't allocate memory");
    }

  int r = erl_drv_output_term (driver_mk_port(drv->port),
                               result, 
                               result_count);

  driver_free (result);
  return r;
}

static int
get_pwall (pwd_drv_t *drv)
{
  size_t pwd_count = 0;
  setpwent ();
  while (getpwent ())
    pwd_count++;
  endpwent ();

  size_t term_count = passwd_term_count ();
  size_t result_count = pwd_count * term_count;
  ErlDrvTermData *result = (ErlDrvTermData *) driver_alloc (sizeof (ErlDrvTermData) * (result_count + 3));
  if (!result)
    {
      fprintf (drv->log, "Couldn't allocate memory for result\n");
      fflush (drv->log);

      return send_error (drv, "error", "Couldn't allocate memory for result");
    }

  char **names = (char **) driver_alloc (sizeof (char *) * pwd_count);
  char **pwds  = (char **) driver_alloc (sizeof (char *) * pwd_count);

  setpwent ();

  size_t result_idx = 0;
  struct passwd *pwd = getpwent ();
  while (pwd)
    {
      fill_passwd (&result[result_idx * term_count], pwd, &names[result_idx], &pwds[result_idx]);
      result_idx++;

      pwd = getpwent ();
    }

  endpwent ();

  result[result_count++] = ERL_DRV_NIL;
  result[result_count++] = ERL_DRV_LIST;
  result[result_count++] = pwd_count + 1;

  int r = erl_drv_output_term (driver_mk_port(drv->port),
                               result,
                               result_count);

  size_t i = 0;
  for (; i < pwd_count; ++i)
    {
      driver_free (pwds[i]);
      driver_free (names[i]);
    }

  driver_free (pwds);
  driver_free (names);
  driver_free (result);
  return r;
}

static ErlDrvTermData *
make_passwd (pwd_drv_t *drv, struct passwd *pwd, size_t *count)
{
  *count = passwd_term_count ();
  ErlDrvTermData *result = (ErlDrvTermData *)driver_alloc (sizeof (ErlDrvTermData) * *count);
  if (!result)
    {
      fprintf (drv->log, "Couldn't allocate memory for result (size: %ld)\n", (long int)*count);
      fflush (drv->log);

      *count = 0;
      return 0;
    }

  fill_passwd (result, pwd, 0, 0);
  return result;
}

static void
fill_passwd (ErlDrvTermData *data, struct passwd *pwd,
             char **name,
             char **passwd)
{
  char *pw_name = pwd->pw_name;
  char *pw_passwd = pwd->pw_passwd;

  size_t len_name = strlen (pw_name);
  size_t len_passwd = strlen (pw_passwd);

  if (name)
    {
      *name = (char *) driver_alloc (sizeof (char) * (len_name + 1));
      memcpy (*name, pw_name, sizeof (char) * (len_name + 1));

      pw_name = *name;
    }

  if (passwd)
    {
      *passwd = (char *) driver_alloc (sizeof (char *) * (len_passwd + 1));
      memcpy (*passwd, pw_passwd, sizeof (char) * (len_passwd + 1));

      pw_passwd = *passwd;
    }

  *data++ = ERL_DRV_ATOM;
  *data++ = driver_mk_atom ("pw_name");
  *data++ = ERL_DRV_STRING;
  *data++ = (ErlDrvTermData) pw_name;
  *data++ = strlen (pwd->pw_name);
  *data++ = ERL_DRV_TUPLE;
  *data++ = 2;

  *data++ = ERL_DRV_ATOM;
  *data++ = driver_mk_atom ("pw_passwd");
  *data++ = ERL_DRV_STRING;
  *data++ = (ErlDrvTermData) pw_passwd;
  *data++ = strlen (pwd->pw_name);
  *data++ = ERL_DRV_TUPLE;
  *data++ = 2;

  *data++ = ERL_DRV_ATOM;
  *data++ = driver_mk_atom ("pw_uid");
  *data++ = ERL_DRV_UINT;
  *data++ = pwd->pw_uid;
  *data++ = ERL_DRV_TUPLE;
  *data++ = 2;

  *data++ = ERL_DRV_ATOM;
  *data++ = driver_mk_atom ("pw_gid");
  *data++ = ERL_DRV_UINT;
  *data++ = pwd->pw_gid;
  *data++ = ERL_DRV_TUPLE;
  *data++ = 2;
  
  *data++ = ERL_DRV_TUPLE;
  *data++ = 4;
}

static size_t 
passwd_term_count ()
{
  return 2 + 3 + 2 +  // username tuple
         2 + 3 + 2 +  // password tuple
         2 + 2 + 2 +  // uid tuple
         2 + 2 + 2 +  // gid tuple
         2;         // total tuple
}

static int
get_grgid (pwd_drv_t *drv, char *cmd)
{
  __gid_t uid = atoi (cmd);
  struct group *grp = getgrgid (uid);
  if (!grp)
    {
       fprintf (drv->log, "getgrgid returns NULL for %s\n", cmd);
       fflush (drv->log);
       
       return send_error (drv, "error", "unknow_gid");
    }
  
  size_t result_count = 0;
  ErlDrvTermData *result = make_group (drv, grp, &result_count);
  if (!result)
    {
       return send_error (drv, "error", "Couldn't allocate memory");
    }

  int r = erl_drv_output_term (driver_mk_port(drv->port),
                               result,
                               result_count);

  driver_free (result);
  return r;
}

static int
get_grnam (pwd_drv_t *drv, char *cmd)
{
  struct group *grp = getgrnam (cmd);
  if (!grp)
    {
      fprintf (drv->log, "getgrnam returns NULL for %s\n", cmd);
      fflush (drv->log);

      return send_error (drv, "error", "unknown_name");
    }

  size_t result_count = 0;
  ErlDrvTermData *result = make_group (drv, grp, &result_count);
  if (!result)
    {
      return send_error (drv, "error", "Couldn't allocate memory");
    }

  int r = erl_drv_output_term (driver_mk_port(drv->port),
                               result,
                               result_count);

  driver_free (result);
  return r;
}

static int
get_grall (pwd_drv_t *drv)
{
  size_t grp_count = 0;
  size_t result_count = 0;
  struct group * grp = NULL;
  setgrent ();
  while ((grp = getgrent ()))
    {
      grp_count++;
      result_count += group_term_count( group_mem_length(grp) );
    }
  endgrent ();
  grp = NULL;

  ErlDrvTermData *result = (ErlDrvTermData *) driver_alloc (sizeof (ErlDrvTermData) * (result_count + 3));
  if (!result)
    {
      fprintf (drv->log, "Couldn't allocate memory for result\n");
      fflush (drv->log);

      return send_error (drv, "error", "Couldn't allocate memory for result");
    }

  char **names = (char **) driver_alloc (sizeof (char *) * grp_count);
  char **pwds  = (char **) driver_alloc (sizeof (char *) * grp_count);
  char ***mems = (char ***) driver_alloc (sizeof (char**) * grp_count);

  setgrent();

  size_t result_idx = 0;
  ErlDrvTermData *result_it = result;
  grp = getgrent();
  while (grp)
    {
      result_it += fill_group (result_it, grp, &names[result_idx], &pwds[result_idx], &mems[result_idx]);
      result_idx++;

      grp = getgrent();
    }

  endgrent();

  *result_it++ = ERL_DRV_NIL;
  *result_it++ = ERL_DRV_LIST;
  *result_it++ = grp_count + 1;

  int r = erl_drv_output_term (driver_mk_port(drv->port),
                               result,
                               result_count + 3);

  size_t i;
  for (i = 0; i < grp_count; ++i)
    {
      driver_free (pwds[i]);
      driver_free (names[i]);

      char ** mem_it = mems[i];
      while (*mem_it)
        {
          driver_free (*mem_it);
          mem_it++;
        }
    }

  driver_free (pwds);
  driver_free (names);
  driver_free (mems);

  driver_free (result);
  return r;
}

static ErlDrvTermData *
make_group (pwd_drv_t *drv, struct group *grp, size_t *count)
{
  size_t gr_mem_len = group_mem_length (grp);

   *count = group_term_count ( gr_mem_len );
   ErlDrvTermData *result = (ErlDrvTermData *)driver_alloc (sizeof (ErlDrvTermData) * *count);
   if (!result)
     {
       fprintf (drv->log, "Couldn't allocate memory for result (size: %ld)\n", (long int)*count);
       fflush (drv->log);
        
       *count = 0;
       return 0;
     }

   fill_group (result, grp, 0, 0, 0);
   return result;
}

static size_t
fill_group (ErlDrvTermData *data, struct group *grp,
             char **name,
             char **passwd,
             char ***mems )
{
   ErlDrvTermData *orig_data = data;

   char *gr_name = grp->gr_name;
   char *gr_passwd = grp->gr_passwd;
   char **gr_mem = grp->gr_mem;
  
   size_t len_name = strlen (gr_name);
   size_t len_passwd = strlen (gr_passwd);
   size_t len_mem = group_mem_length(grp);

   unsigned int it;
   
   if (name)
     {
       *name = (char *) driver_alloc (sizeof (char) * (len_name + 1));
       memcpy (*name, gr_name, sizeof (char) * (len_name + 1));

       gr_name = *name;
     }

   if (passwd)
     {
       *passwd = (char *) driver_alloc (sizeof (char *) * (len_passwd + 1));
       memcpy (*passwd, gr_passwd, sizeof (char) * (len_passwd + 1));

       gr_passwd = *passwd;
     }

   if (mems)
     {
       *mems = (char **) driver_alloc (sizeof (char **) * (len_mem + 1));

       for ( it = 0; it < len_mem; it++ )
         {
           size_t len_mem_name = strlen(gr_mem[it]);
           (*mems)[it] = (char *) driver_alloc (sizeof(char *) * (len_mem_name + 1));
           memcpy ( (*mems)[it], gr_mem[it], sizeof (char) * (len_mem_name + 1));
         }
       gr_mem = *mems;

       (*mems)[it] = NULL;
     }

   *data++ = ERL_DRV_ATOM;
   *data++ = driver_mk_atom ("gr_name");
   *data++ = ERL_DRV_STRING;
   *data++ = (ErlDrvTermData) gr_name;
   *data++ = len_name;
   *data++ = ERL_DRV_TUPLE;
   *data++ = 2;

   *data++ = ERL_DRV_ATOM;
   *data++ = driver_mk_atom ("gr_passwd");
   *data++ = ERL_DRV_STRING;
   *data++ = (ErlDrvTermData) gr_passwd;
   *data++ = len_passwd;
   *data++ = ERL_DRV_TUPLE;
   *data++ = 2;

   *data++ = ERL_DRV_ATOM;
   *data++ = driver_mk_atom ("gr_gid");
   *data++ = ERL_DRV_UINT;
   *data++ = grp->gr_gid;
   *data++ = ERL_DRV_TUPLE;
   *data++ = 2;

   *data++ = ERL_DRV_ATOM;
   *data++ = driver_mk_atom ("gr_mem");

   for ( it = 0; it < len_mem; it++ )
     {
       *data++ = ERL_DRV_STRING;
       *data++ = (ErlDrvTermData) gr_mem[it];
       *data++ = strlen(gr_mem[it]);
     }

   *data++ = ERL_DRV_NIL;
   *data++ = ERL_DRV_LIST;
   *data++ = len_mem + 1;

   *data++ = ERL_DRV_TUPLE;
   *data++ = 2;

   *data++ = ERL_DRV_TUPLE;
   *data++ = 4;

   return data - orig_data;
}

static size_t
group_mem_length ( struct group * grp )
{
  size_t len_mem = 0;
  char **it = grp->gr_mem;
  while (*(it++)) len_mem++;
  return len_mem;
}
  

static size_t
group_term_count ( size_t gr_mem_len )
{
  return 2 + 3 + 2 + // groupname tuple
         2 + 3 + 2 + // password tuple
         2 + 2 + 2 + // gid tuple
         (2 + 3*gr_mem_len + 1 + 2 + 2) + // member list: atom, list of strings, nil, list term, tuple term
         2; // total tuple
}

