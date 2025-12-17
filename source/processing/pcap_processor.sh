#!/bin/bash
# pcap_processor.sh
# Usage: ./pcap_processor.sh [pcap_in] [csv_out] [pcap_done]
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PCAP_IN=${1:-$PROJECT_ROOT/output/pcap_in}
FINAL_CSV=${FINAL_CSV:-$PROJECT_ROOT/output/final_csv/Predict.csv}
# Thư mục tạm để CICFlowMeter xuất CSV, tránh đụng Predict.csv
CSV_OUT=${2:-$PROJECT_ROOT/output/final_csv/tmp}
PROCESSED=${3:-$PROJECT_ROOT/output/pcap_done}

# Mặc định (repo-relative)
JAVA_LIB_DIR=${JAVA_LIB_DIR:-$PROJECT_ROOT/CICFlowMeter/jnetpcap/linux/jnetpcap-1.4.r1425}
JNETJAR=${JNETJAR:-$PROJECT_ROOT/CICFlowMeter/jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar}
CICJAR=${CICJAR:-$PROJECT_ROOT/CICFlowMeter/build/libs/CICFlowMeter-4.0.jar}
SLF4J_API=${SLF4J_API:-$PROJECT_ROOT/ciclib/slf4j-api-1.7.36.jar}
SLF4J_IMPL=${SLF4J_IMPL:-$PROJECT_ROOT/ciclib/slf4j-simple-1.7.36.jar}
TIKA_CORE=${TIKA_CORE:-$PROJECT_ROOT/ciclib/tika-core-1.24.jar}
TIKA_PARSERS=${TIKA_PARSERS:-$PROJECT_ROOT/ciclib/tika-parsers-1.24.jar}
COMMONS_IO=${COMMONS_IO:-$PROJECT_ROOT/ciclib/commons-io-2.11.0.jar}
COMMONS_MATH=${COMMONS_MATH:-$PROJECT_ROOT/ciclib/commons-math3-3.6.1.jar}

# nếu CICJAR chưa có, thử tìm trong gradle cache (fallback)
if [ ! -f "$CICJAR" ]; then
  CICJAR=$(find "$PROJECT_ROOT" -maxdepth 6 -name "CICFlowMeter-4.0.jar" 2>/dev/null | head -n1)
fi
if [ ! -f "$SLF4J_API" ]; then
  SLF4J_API=$(find "$PROJECT_ROOT" -maxdepth 6 -name "slf4j-api-*.jar" 2>/dev/null | head -n1)
fi
if [ ! -f "$SLF4J_IMPL" ]; then
  SLF4J_IMPL=$(find "$PROJECT_ROOT" -maxdepth 6 -name "slf4j-simple-*.jar" 2>/dev/null | head -n1)
fi
if [ ! -f "$TIKA_CORE" ]; then
  TIKA_CORE=$(find "$PROJECT_ROOT" -maxdepth 6 -name "tika-core-*.jar" 2>/dev/null | head -n1)
fi
if [ ! -f "$TIKA_PARSERS" ]; then
  TIKA_PARSERS=$(find "$PROJECT_ROOT" -maxdepth 6 -name "tika-parsers-*.jar" 2>/dev/null | head -n1)
fi
if [ ! -f "$COMMONS_IO" ]; then
  COMMONS_IO=$(find "$PROJECT_ROOT" -maxdepth 6 -name "commons-io-*.jar" 2>/dev/null | head -n1)
fi
if [ ! -f "$COMMONS_MATH" ]; then
  COMMONS_MATH=$(find "$PROJECT_ROOT" -maxdepth 6 -name "commons-math3-*.jar" 2>/dev/null | head -n1)
fi

if [ -z "$JAVA_LIB_DIR" ] || [ ! -f "$JNETJAR" ] || [ ! -f "$CICJAR" ] || [ ! -f "$SLF4J_API" ] || [ ! -f "$SLF4J_IMPL" ] || [ ! -f "$TIKA_CORE" ] || [ ! -f "$TIKA_PARSERS" ] || [ ! -f "$COMMONS_IO" ] || [ ! -f "$COMMONS_MATH" ]; then
  echo "[ERROR] Thiết lập JAVA_LIB_DIR/JNETJAR/CICJAR/SLF4J_API/SLF4J_IMPL/TIKA_CORE/TIKA_PARSERS/COMMONS_IO/COMMONS_MATH chưa đúng."
  echo "Hiện giá trị:"
  echo "  JAVA_LIB_DIR=$JAVA_LIB_DIR"
  echo "  JNETJAR=$JNETJAR"
  echo "  CICJAR=$CICJAR"
  echo "  SLF4J_API=$SLF4J_API"
  echo "  SLF4J_IMPL=$SLF4J_IMPL"
  echo "  TIKA_CORE=$TIKA_CORE"
  echo "  TIKA_PARSERS=$TIKA_PARSERS"
  echo "  COMMONS_IO=$COMMONS_IO"
  echo "  COMMONS_MATH=$COMMONS_MATH"
  echo "Hãy chỉnh các biến này (export trước khi chạy) hoặc sửa trực tiếp trong script."
  exit 1
fi

echo "[PCAP PROCESSOR] JAVA_LIB_DIR=$JAVA_LIB_DIR"
echo "[PCAP PROCESSOR] JNETJAR=$JNETJAR"
echo "[PCAP PROCESSOR] CICJAR=$CICJAR"
echo "[PCAP PROCESSOR] SLF4J_API=$SLF4J_API"
echo "[PCAP PROCESSOR] SLF4J_IMPL=$SLF4J_IMPL"
echo "[PCAP PROCESSOR] TIKA_CORE=$TIKA_CORE"
echo "[PCAP PROCESSOR] TIKA_PARSERS=$TIKA_PARSERS"
echo "[PCAP PROCESSOR] COMMONS_IO=$COMMONS_IO"
echo "[PCAP PROCESSOR] COMMONS_MATH=$COMMONS_MATH"
echo "[PCAP PROCESSOR] FINAL_CSV=$FINAL_CSV"
echo "[PCAP PROCESSOR] CSV_OUT=$CSV_OUT"

mkdir -p "$PCAP_IN" "$PROCESSED" "$(dirname "$FINAL_CSV")" "$CSV_OUT"

while true; do
  for f in "$PCAP_IN"/*.pcap; do
    [ -e "$f" ] || continue
    done_marker="${f}.done"
    if [ -f "$done_marker" ]; then
      continue
    fi

    # skip files still being written (mtime < 2s)
    if [ $(( $(date +%s) - $(stat -c %Y "$f") )) -lt 2 ]; then
      continue
    fi

    echo "[PCAP PROCESSOR] Processing $f ..."
    TMPDIR=$(mktemp -d)
    cp "$f" "$TMPDIR/"

    # run CICFlowMeter CLI on TMPDIR -> output to CSV_OUT (tmp)
    java -Djava.library.path="$JAVA_LIB_DIR" \
          -cp "$SLF4J_API:$SLF4J_IMPL:$TIKA_CORE:$TIKA_PARSERS:$COMMONS_IO:$COMMONS_MATH:$CICJAR:$JNETJAR:$JAVA_LIB_DIR/*" \
         cic.cs.unb.ca.ifm.Cmd \
         "$TMPDIR" "$CSV_OUT"
    rc=$?
    if [ $rc -eq 0 ]; then
      # append all generated CSVs into FINAL_CSV (keep single header)
      for csv_new in "$CSV_OUT"/*.csv; do
        [ -e "$csv_new" ] || continue
        if [ ! -f "$FINAL_CSV" ]; then
          mv "$csv_new" "$FINAL_CSV"
        else
          tail -n +2 "$csv_new" >> "$FINAL_CSV"
          rm -f "$csv_new"
        fi
      done
      touch "$done_marker"
      mv "$f" "$PROCESSED/"
      echo "[PCAP PROCESSOR] Done $f -> appended to $FINAL_CSV"
    else
      echo "[PCAP PROCESSOR] CICFlowMeter failed on $f (rc=$rc)"
      sleep 2
    fi
    rm -rf "$TMPDIR"
  done
  sleep 10
done
