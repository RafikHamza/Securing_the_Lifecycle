import unittest
import tempfile
import subprocess
from pathlib import Path
from cpd_verifier.model import BufferContract, Contract
from cpd_verifier.generator import generate_artifacts

MAIN_C = """#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "test_cpd_verifier.h"

// Dummy transport sink
int test_transport(const uint8_t *data, size_t length) {
    int sum = 0;
    for (size_t i = 0; i < length; i++) {
        sum += data[i];
    }
    printf("SINK_SUM=%d\\n", sum);
    return 0;
}

int main() {
    uint8_t secret[16];
    memset(secret, 0xAA, 16); // Fill with 0xAA (170)
    
    printf("BEFORE: %d\\n", secret[0]);
    
    // Wrapper name comes from first allowed_sink
    int status = safe_send(secret, 16);
    
    // Check if zeroized
    int all_zeros = 1;
    for (int i = 0; i < 16; i++) {
        if (secret[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    
    if (all_zeros) {
        printf("ZEROIZED\\n");
    } else {
        printf("NOT_ZEROIZED\\n");
    }
    
    return status;
}
"""

class CPDVerifierRuntimeIntegrationTests(unittest.TestCase):
    def test_runtime_zeroization(self):
        contract = Contract(
            module="test",
            buffers=[
                BufferContract(
                    name="secret",
                    element_type="uint8_t",
                    sensitive=True,
                    must_zeroize=True,
                    forbid_post_send_use=True,
                    allowed_sinks=("safe_send",),
                    forbidden_sinks=(),
                    transport_sink="test_transport"
                )
            ],
            sources=(),
            sinks=(),
            zeroizers=()
        )
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # 1. Generate artifacts
            written_files = generate_artifacts(contract, temp_path)
            self.assertEqual(len(written_files), 3)
            
            # 2. Write main.c
            main_path = temp_path / "main.c"
            main_path.write_text(MAIN_C, encoding="utf-8")
            
            # 3. Compile
            bin_path = temp_path / "test_bin.exe"
            compile_cmd = ["gcc", "-o", str(bin_path), str(main_path), str(temp_path / "test_cpd_verifier.c")]
            
            try:
                subprocess.run(compile_cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                self.fail(f"Compilation failed:\\n{e.stderr}")
                
            # 4. Run binary
            try:
                run_res = subprocess.run([str(bin_path)], check=True, capture_output=True, text=True)
                output = run_res.stdout
            except subprocess.CalledProcessError as e:
                self.fail(f"Binary execution failed:\\n{e.stderr}")
                
            # 5. Assertions
            self.assertIn("BEFORE: 170", output)
            self.assertIn("SINK_SUM=2720", output) # 170 * 16 = 2720
            self.assertIn("ZEROIZED", output)

if __name__ == "__main__":
    unittest.main()
