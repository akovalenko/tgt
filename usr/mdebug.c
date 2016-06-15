#include "pcs_malloc.h"
#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "driver.h"
#include "target.h"
#include "scsi.h"
#include "iscsi/iscsid.h"
#include "work.h"


#define TGTD_PCS_LOGFILE "/var/log/tgtd-pcs.log"
#define TGTD_PCS_EACH_SECONDS 60

#define PCSMALLOC_DUMP_LEVEL 1
#define COMMAND_DUMP_LEVEL 1

/* Borrow log protos from pcs, avoid importing many more pcs headers */

int pcs_set_logfile(const char* path);
void pcs_log_terminate(void);
void pcs_log(int level, const char *fmt, ...) __printf(2, 3);


static struct tgt_work mdebug_work;
extern struct list_head sessions_list;

void mdebug_task_dump(void)
{
  struct iscsi_session *session;
  struct iscsi_task *task;

  list_for_each_entry(session, &sessions_list, hlist) {
    list_for_each_entry(task, &session->cmd_list, c_hlist) {
      pcs_log(COMMAND_DUMP_LEVEL,
              "task:%p pending:%lu in_scsi:%lu tag:%"PRIx64
              "OBUF:%u (@%p) IBUF:%u (@%p)",

              task, task_pending(task), task_in_scsi(task),
              task->tag,
              scsi_get_out_length(&task->scmd),
              scsi_get_out_buffer(&task->scmd),
              scsi_get_in_length(&task->scmd),
              scsi_get_in_buffer(&task->scmd));
    }
  }
}

void mdebug_work_handler(void* arg)
{
  pcs_malloc_dump(PCSMALLOC_DUMP_LEVEL);
  mdebug_task_dump();
  add_work(&mdebug_work,TGTD_PCS_EACH_SECONDS);
}


int mdebug_start(void)
{
  pcs_set_logfile(TGTD_PCS_LOGFILE);
  pcs_malloc_debug_enable();
  mdebug_work.func = mdebug_work_handler;
  mdebug_work.data = &mdebug_work;
  add_work(&mdebug_work,TGTD_PCS_EACH_SECONDS);
  return 0;
}

void mdebug_stop(void)
{
  pcs_log_terminate();
}
