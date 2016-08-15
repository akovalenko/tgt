#include <stdint.h>
#include <stdlib.h>
#include "memdebug.h"
#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "driver.h"
#include "target.h"
#include "scsi.h"
#include "iscsi/iscsid.h"
#include "work.h"


#define TGTD_PCS_EACH_SECONDS 60

static struct tgt_work mdebug_work;
extern struct list_head sessions_list;

void mdebug_map_tcp_iscsi_conn(void (*fn)(struct iscsi_connection *conn));

#define SHOW log_debug

static void mdebug_show_task(struct iscsi_task *task) {
	SHOW(
		"task:%p OP:%d pending:%lu in_scsi:%lu tag:%"PRIx64
		" OBUF:%u IBUF:%u CST:%d Cref:%u\n",
		task, task->req.opcode & ISCSI_OPCODE_MASK,
		task_pending(task), task_in_scsi(task),
		task->tag,
		scsi_get_out_length(&task->scmd),
		scsi_get_in_length(&task->scmd),
		task->conn->state, task->conn->refcount);
}

void mdebug_dump_conn_tasks(struct iscsi_connection *conn)
{
	struct iscsi_task *task;
	SHOW("Connection: %p\n",conn);
	list_for_each_entry(task, &conn->task_list, c_siblings) {
		mdebug_show_task(task);
	}
}

void mdebug_task_dump(void)
{
	struct iscsi_session *session;
	struct iscsi_task *task;

	SHOW("---< PER-SESSION TASK DUMP\n");
	list_for_each_entry(session, &sessions_list, hlist) {
		list_for_each_entry(task, &session->cmd_list, c_hlist) {
			mdebug_show_task(task);
		}
	}
	SHOW("---> PER-SESSION TASK DUMP END\n");
	SHOW("---< PER-CONNECTION TASK DUMP\n");
	mdebug_map_tcp_iscsi_conn(mdebug_dump_conn_tasks);
	SHOW("---> PER-CONNECTION TASK DUMP END\n");
}

static void EPRINTF_LINE(const char *str, void* arg) {
	(void)arg;
	SHOW("%s\n",str);
}

void mdebug_memory_dump(void) {
	SHOW("---< MEMORY ALLOCATION DUMP:\n");
	memdebug_dump_stats(EPRINTF_LINE,NULL);
	SHOW("---> MEMORY ALLOCATION DUMP END\n");
}

void mdebug_work_handler(void* arg)
{
	mdebug_task_dump();
	mdebug_memory_dump();
	add_work(&mdebug_work,TGTD_PCS_EACH_SECONDS);
}


int mdebug_start(void)
{
	memdebug_set_enabled(true);
	mdebug_work.func = mdebug_work_handler;
	mdebug_work.data = &mdebug_work;
	add_work(&mdebug_work,TGTD_PCS_EACH_SECONDS);
	return 0;
}

void mdebug_stop(void)
{
}
