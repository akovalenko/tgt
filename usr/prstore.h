#ifndef __PRSTORE_H
#define __PRSTORE_H

#include "list.h"
#include "tgtd.h"

struct registration;

struct pr_store {
	int enable;
	int fd;
	int nslots;
	long *free_slot_mask;
};

/* start prstore thread */
int prstore_engine_init(void);
/* stop prstore thread and flush queues */
void prstore_engine_deinit(void);

/* open store for a LUN */
int prstore_open(struct scsi_lu *lu);
/* close store for a LUN */
int prstore_close(struct scsi_lu *lu);
/* update slot in a store */
int prstore_update(struct registration *reg, struct scsi_cmd *cmd);
/* free slot in a store */
int prstore_delete(int slot, struct scsi_cmd *cmd);

#endif
