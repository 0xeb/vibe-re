#include "analysis_types.hpp"

#include <vector>

namespace oceandrift::analysis {

std::vector<FunctionEvidence> full_evidence_catalog() {
  return {
      // startup
      startup_autorun_evidence(),
      // config / decode
      decode_hex_xor_evidence(),
      config_loader_evidence(),
      // graph API
      graph_refresh_evidence(),
      graph_request_evidence(),
      // host profiling
      host_profile_evidence(),
      mac_address_evidence(),
      machine_guid_evidence(),
      md5_hex_evidence(),
      wmi_processor_evidence(),
      // beacon / C2
      command_dispatch_evidence(),
      worker_loop_evidence(),
      beacon_init_evidence(),
      beacon_ctx_init_evidence(),
      start_workers_evidence(),
      shell_exec_evidence(),
      upload_file_evidence(),
      publish_result_evidence(),
      select_task_evidence(),
      download_task_evidence(),
      spawn_detached_evidence(),
      escape_json_evidence(),
      // main
      main_workflow_evidence(),
  };
}

}  // namespace oceandrift::analysis
