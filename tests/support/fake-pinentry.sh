#!/bin/sh
# Test stand-in for pinentry, speaking the Assuan subset the daemon uses.
#
# Reads answers from $FAKE_PINENTRY_DIR/pins, one per GETPIN, in order
# across invocations. Special answers: CANCEL (user cancelled), HANG
# (never answers), FAIL (reply ERR 83918950 Inappropriate ioctl for device
# to GETPIN, then exit — a pinentry that cannot show its window) and EXIT
# (exit without replying). Logs every command except data to
# $FAKE_PINENTRY_DIR/log and its PID to $FAKE_PINENTRY_DIR/pid.
dir=$FAKE_PINENTRY_DIR
echo $$ > "$dir/pid"
echo "STARTED" >> "$dir/log"
echo "OK Pleased to meet you"
while IFS= read -r line; do
    printf '%s\n' "$line" >> "$dir/log"
    case "$line" in
        GETPIN)
            n=$(cat "$dir/count" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$dir/count"
            pin=$(sed -n "${n}p" "$dir/pins")
            case "$pin" in
                CANCEL) echo "ERR 83886179 Operation cancelled <Pinentry>" ;;
                HANG) exec sleep 3600 ;;
                FAIL) echo "ERR 83918950 Inappropriate ioctl for device"; exit 0 ;;
                EXIT) exit 0 ;;
                *) printf 'D %s\n' "$(printf '%s' "$pin" | sed 's/%/%25/g')"; echo OK ;;
            esac ;;
        BYE) echo "OK closing connection"; exit 0 ;;
        *) echo OK ;;
    esac
done
