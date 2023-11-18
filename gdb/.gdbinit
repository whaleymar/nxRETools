target extended-remote 10.0.0.59:22225
monitor wait application
define my_bt
  set $frame = $fp
  set $prev_frame = 0
  while $frame != 0 && $prev_frame != $frame
      set $prev_frame = $frame
      p/x ((unsigned long long *)$frame)[1]
      set $frame = ((unsigned long long *)$frame)[0]
  end
end