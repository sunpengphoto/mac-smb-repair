#!/bin/zsh

# macOS SMB 修复器
# 检测当前用户 NetAuthSysAgent 的已知 SMB 挂载阻塞特征；只有连续两次确认后才结束该进程。
# 不访问网络、不读取凭据、不包含服务器或账户信息，也不保存采样内容。
# 用法：双击运行；或在终端运行 ./NetAuthSMBRepair.command --check 仅检测。

umask 077
TASK_UID=$(/usr/bin/id -u)
TASK_TMP=''
TASK_CHECK_ONLY=0

cleanup() {
  if [[ -n "$TASK_TMP" && "$TASK_TMP" == /tmp/netauth-smb-repair.* && -d "$TASK_TMP" ]]; then
    /bin/rm -f "$TASK_TMP/first.txt" "$TASK_TMP/second.txt"
    /bin/rmdir "$TASK_TMP" 2>/dev/null
  fi
  TASK_TMP=''
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

finish() {
  local task_result="$1"
  cleanup
  print
  if [[ -t 0 ]]; then
    read -r '?按回车结束；终端窗口可以直接关闭。'
  fi
  exit "$task_result"
}

process_identity() {
  /bin/ps -p "$TASK_PID" -o lstart= -o uid= -o comm= 2>/dev/null
}

# 返回值：0=发现特征，1=未发现，2=无法可靠解析。
# 只匹配同一调用路径；不会因为报告不同位置的关键词而误判。
analyze_sample() {
  /usr/bin/awk '
    /^Call graph:/ && !graph_seen { graph_seen = 1; in_graph = 1; next }
    in_graph && /^(Total number in stack|Sort by top of stack|Binary Images:)/ { in_graph = 0 }
    in_graph && /^[[:space:]]*[0-9]+ Thread_/ {
      total = $1 + 0
      is_main = ($0 ~ /com\.apple\.main-thread/)
      if (is_main && total >= 100) main_seen = 1
      thread_seen = 1
      for (key in path) delete path[key]
      next
    }
    in_graph && total >= 100 && match($0, /[0-9]+ /) {
      depth = RSTART
      count = substr($0, RSTART, RLENGTH) + 0
      symbol = substr($0, RSTART + RLENGTH)
      for (key in path) if (key + 0 >= depth) delete path[key]
      path[depth] = symbol
      if (count / total < 0.95) next

      has_sync = has_lock = has_mount = has_sid = has_rpc = 0
      for (key in path) {
        frame = path[key]
        if (frame ~ /^objc_sync_enter /) has_sync = 1
        if (frame ~ /^_os_unfair_lock_lock_slow /) has_lock = 1
        if (frame ~ /^(SMBNetFsMount|SMB_Mount|smb_mount) /) has_mount = 1
        if (frame ~ /^(GetNetworkAccountSID|GetAccountNameSID|LsarOpenPolicy2)[ (]/) has_sid = 1
        if (frame ~ /^rpc__cn_(call_transceive|assoc_receive_frag) /) has_rpc = 1
      }
      if (is_main && has_sync && has_lock && symbol ~ /^__ulock_wait2? /) main_blocked = 1
      if (!is_main && has_mount && has_sid && has_rpc && symbol ~ /^__psynch_cvwait /) smb_blocked = 1
    }
    END {
      if (!main_seen || !thread_seen) exit 2
      if (main_blocked && smb_blocked) exit 0
      exit 1
    }
  ' "$1"
}

case "${1-}" in
  '') ;;
  --check) TASK_CHECK_ONLY=1 ;;
  *) print '用法：双击运行，或使用 --check 仅检测。'; finish 2 ;;
esac
if (( $# > 1 )); then
  print '参数过多。'
  finish 2
fi

print 'NetAuthSysAgent SMB 阻塞检测与修复'
print

if [[ "$TASK_UID" == '0' ]]; then
  print '请以普通用户运行，不要使用 sudo。'
  finish 2
fi
if [[ ! -x /usr/bin/sample ]]; then
  print '当前 macOS 缺少 sample 工具，无法进行安全检测。未做修改。'
  finish 2
fi

TASK_PID=$(/usr/bin/pgrep -U "$TASK_UID" -x NetAuthSysAgent)
TASK_LOOKUP_RESULT=$?
if (( TASK_LOOKUP_RESULT == 1 )); then
  print '未发现问题：当前没有运行中的 NetAuthSysAgent。未做修改。'
  finish 0
elif (( TASK_LOOKUP_RESULT != 0 )) || [[ "$TASK_PID" != <-> ]]; then
  print '无法唯一确定当前用户的进程。未做修改。'
  finish 2
fi

TASK_IDENTITY=$(process_identity)
if [[ -z "$TASK_IDENTITY" ]]; then
  print '进程已退出。未做修改。'
  finish 0
fi
TASK_TMP=$(/usr/bin/mktemp -d /tmp/netauth-smb-repair.XXXXXXXX)
if [[ -z "$TASK_TMP" || ! -d "$TASK_TMP" ]]; then
  print '无法建立临时检测目录。未做修改。'
  finish 2
fi

print '正在进行两次采样检测，通常需要约 10–20 秒……'
for TASK_PASS in first second; do
  if [[ "$(process_identity)" != "$TASK_IDENTITY" ]]; then
    print '检测期间进程已退出或更换。未做修改。'
    finish 0
  fi
  if ! /usr/bin/sample "$TASK_PID" 3 10 -file "$TASK_TMP/$TASK_PASS.txt" >/dev/null 2>&1; then
    print '采样未完成，无法判断。未做修改。'
    finish 2
  fi
  analyze_sample "$TASK_TMP/$TASK_PASS.txt"
  TASK_ANALYSIS_RESULT=$?
  if (( TASK_ANALYSIS_RESULT == 1 )); then
    print '未发现已知 SMB 持续阻塞特征。未做修改。'
    finish 0
  elif (( TASK_ANALYSIS_RESULT != 0 )); then
    print '采样信息不足或格式不受支持，无法判断。未做修改。'
    finish 2
  fi
  if [[ "$TASK_PASS" == first ]]; then
    print '首次采样发现疑似阻塞，正在再次确认……'
    /bin/sleep 2
  fi
done

if [[ "$(process_identity)" != "$TASK_IDENTITY" ]]; then
  print '原进程已退出或更换。未做修改。'
  finish 0
fi
print '两次采样均发现持续阻塞特征。'
if (( TASK_CHECK_ONLY )); then
  print '只检测模式：未做修改。'
  finish 0
fi

print '正在结束已确认阻塞的进程……'
if ! /bin/kill -TERM "$TASK_PID" 2>/dev/null; then
  print '未能结束进程，修复未完成。'
  finish 2
fi
for TASK_ATTEMPT in 1 2 3 4 5; do
  if [[ "$(process_identity)" != "$TASK_IDENTITY" ]]; then
    print '原进程已退出；macOS 会在需要时重新启动它。请重试原来的连接。'
    finish 0
  fi
  /bin/sleep 1
done
print '已发送终止信号，但原进程仍未退出，修复未完成。'
finish 2
