#ifndef TB_TUI_H
#define TB_TUI_H

#include "browser.h"

/* Launch the interactive raw-termios TUI event loop. Returns 0 on clean exit. */
int tb_tui_run(TbBrowser *b);

#endif /* TB_TUI_H */
