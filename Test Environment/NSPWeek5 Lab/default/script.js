import http from "k6/http";
import { check, sleep } from "k6";

// --- Configuration ---
const TARGET_URL = __ENV.TARGET_URL || "http://localhost:8080";
const TARGET_VUS = __ENV.VUS ? parseInt(__ENV.VUS) : 10;

const THINK_TIME_MIN = __ENV.THINK_TIME_MIN
  ? parseFloat(__ENV.THINK_TIME_MIN)
  : 0.5;
const THINK_TIME_MAX = __ENV.THINK_TIME_MAX
  ? parseFloat(__ENV.THINK_TIME_MAX)
  : 2.0;

function randomThinkTime(min, max) {
  const low = Math.max(0, Math.min(min, max));
  const high = Math.max(min, max);
  return low + Math.random() * (high - low);
}

// --- Test Lifecycle (Options) ---
export const options = {
  stages: [
    { duration: "30s", target: TARGET_VUS },
    { duration: "1m", target: TARGET_VUS },
    { duration: "30s", target: 0 },
  ],
};

export default function () {
  // --- ส่วนที่แก้ไข: เพิ่ม Custom Marker (Request ID) ---
  // __VU คือ ID ของ Virtual User นั้นๆ
  // __ITER คือ ลำดับรอบการทำงานของ VU นั้น
  const params = {
    headers: {
      "X-K6-Request-ID": `vu-${__VU}-iter-${__ITER}`,
      "Content-Type": "application/json",
    },
  };

  // 1. Send Request พร้อมส่ง params (ที่มี headers) ไปด้วย
  const res = http.get(TARGET_URL, params);

  // 2. Validate Outcome
  check(res, {
    "is status 200 (Done Correctly)": (r) => r.status === 200,
    "is status 50x (Crash/Fail)": (r) => r.status >= 500,
    "is status 429 (Refusal)": (r) => r.status === 429,
  });

  // 3. Think Time (Random)
  sleep(randomThinkTime(THINK_TIME_MIN, THINK_TIME_MAX));
}
