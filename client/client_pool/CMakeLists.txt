project("Concord Client Pool")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

file (GLOB util_headers "../../util/include/*.h"
		"../../util/include/*.hpp")
file (GLOB logging_headers "../../logging/include/*.hpp")
file (GLOB external_headers "*.hpp"
		"../../kvbc/include/db_interfaces.h"
		"../../kvbc/include/kv_types.hpp"
		"../../kvbc/include/KVBCInterfaces.h"
		"../../threshsign/src/*.h")
file (GLOB bft_engine_headers "../../bftengine/include/bftengine/*.hpp"
		"../../bftengine/src/bftengine/*.hpp")
file (GLOB comm_headers "../../communication/include/communication/*.h"
		"../../communication/include/communication/*.hpp"
		"../../secretsmanager/include/secret_data.h")
file (GLOB bft_headers "../../bftclient/include/bftclient/*.h"
		"../../bftclient/src/*.h"
		"../../secretsmanager/include/secret_data.h"
		"../../diagnostics/include/*.h")
file(GLOB relic_headers "../../threshsign/include/threshsign/bls/relic/*.h")

get_property(perf_include GLOBAL PROPERTY PERF_MANAGER_INCLUDE_DIR)

install (FILES ${external_headers} ${util_headers} DESTINATION include/external)
install (FILES ${relic_headers} DESTINATION include/external/bls/relic)
install (FILES ${logging_headers}  ../../threshsign/include/threshsign/ThresholdSignaturesTypes.h DESTINATION include/config)
install (FILES ${bft_engine_headers} ${util_headers} ../../util/include/Metrics.hpp DESTINATION include/bftengine)
install (FILES ${comm_headers} ${logging_headers} DESTINATION include/communication)
install (FILES ../../storage/include/storage/db_interface.h ${util_headers} DESTINATION include/storage)
install (FILES ${bft_headers} DESTINATION include/bftclient)
install (FILES ${util_headers} ${logging_headers} DESTINATION include/)
install (FILES ${perf_include}/PerformanceManager.hpp ${perf_include}/SlowdownManager.hpp ${perf_include}/Helper.hpp DESTINATION include/)

file(GLOB concord_client_pool_sources "*.cpp"
		"../../threshsign/src/*.cpp"
		"src/*.cpp")
set(bls_relic_source_files1
		../../threshsign/src/bls/relic/BlsAccumulatorBase.cpp
		../../threshsign/src/bls/relic/BlsAlmostMultisigAccumulator.cpp
		../../threshsign/src/bls/relic/BlsAlmostMultisigCoefficients.cpp
		../../threshsign/src/bls/relic/BlsBatchVerifier.cpp
		../../threshsign/src/bls/relic/BlsMultisigAccumulator.cpp
		../../threshsign/src/bls/relic/BlsMultisigKeygen.cpp
		../../threshsign/src/bls/relic/BlsMultisigVerifier.cpp
		../../threshsign/src/bls/relic/BlsNumTypes.cpp
		../../threshsign/src/bls/relic/BlsPolynomial.cpp
		../../threshsign/src/bls/relic/BlsPublicParameters.cpp
		../../threshsign/src/bls/relic/BlsThresholdAccumulator.cpp
		../../threshsign/src/bls/relic/BlsThresholdAccumulatorBaseExports.cpp
		../../threshsign/src/bls/relic/BlsThresholdFactory.cpp
		../../threshsign/src/bls/relic/BlsThresholdKeygen.cpp
		../../threshsign/src/bls/relic/BlsThresholdSigner.cpp
		../../threshsign/src/bls/relic/BlsThresholdVerifier.cpp
		../../threshsign/src/bls/relic/FastMultExp.cpp
		../../threshsign/src/bls/relic/LagrangeInterpolation.cpp
		../../threshsign/src/bls/relic/Library.cpp
		)

set(corebft_source_files1
		../../bftengine/src/bcstatetransfer/InMemoryDataStore.cpp
		../../bftengine/src/bftengine/messages/MessageBase.cpp
		../../bftengine/src/bftengine/messages/ClientReplyMsg.cpp
		../../bftengine/src/bftengine/messages/ClientRequestMsg.cpp
		../../bftengine/src/preprocessor/messages/ClientPreProcessRequestMsg.cpp
		../../bftengine/src/preprocessor/messages/ClientBatchRequestMsg.cpp
		../../bftengine/src/bcstatetransfer/STDigest.cpp
		)

include_directories(../../threshsign/include/)
include_directories(../../bftengine/include/bcstatetransfer/)
add_library(concord_client_pool STATIC
		${concord_client_pool_sources}
		)
get_property(thresh_include GLOBAL PROPERTY thresh_include_folder)
target_include_directories(concord_client_pool PUBLIC include)
target_include_directories(concord_client_pool PRIVATE ${thresh_include})
target_include_directories(concord_client_pool PUBLIC ${perf_include})
target_include_directories(concord_client_pool PUBLIC ../../bftengine/cmf)

target_link_libraries(concord_client_pool PUBLIC
		${Boost_LIBRARIES}
		${yaml-cpp_LIBRARIES}
		logging
		concord_utils
		bftclient
		bftclient_new
		kvbc
		util
		threshsign
		concord_config)

add_library(concord_client_pool_shared SHARED
		${concord_client_pool_sources}
		${bls_relic_source_files1}
		${corebft_source_files1}
		../../threshsign/src/ThresholdSignaturesTypes.cpp
		../../threshsign/src/bls/relic/BlsNumTypes.cpp
		../../threshsign/src/bls/relic/BlsThresholdFactory.cpp
		)
target_include_directories(concord_client_pool_shared PRIVATE ${thresh_include})
target_link_libraries(concord_client_pool_shared PUBLIC
		${Boost_LIBRARIES}
		${CRYPTOPP_LIBRARIES}
		logging
		concord_utils_shared
		bftclient_shared
		bftclient_new
		util_shared
		concord_config)

target_include_directories(concord_client_pool_shared PUBLIC include)
target_include_directories(concord_client_pool_shared PUBLIC ../../logging/include)
target_include_directories(concord_client_pool_shared PUBLIC ../../logging/include)
target_include_directories(concord_client_pool_shared PUBLIC ../../util/include)
target_include_directories(concord_client_pool_shared PUBLIC ../../communication/include/communication)
target_include_directories(concord_client_pool_shared PUBLIC ../../bftclient/include/bftclient)
target_include_directories(concord_client_pool_shared PUBLIC ../../threshsign/src)
target_include_directories(concord_client_pool_shared PUBLIC ../../storage/include/)
target_include_directories(concord_client_pool_shared PUBLIC ../../bftengine/cmf)

# Hack for including SysConsts.hpp
target_include_directories(concord_client_pool_shared PUBLIC ../../bftengine/src/bftengine)
target_include_directories(concord_client_pool_shared PUBLIC ../../include/bftengine)

target_include_directories(concord_client_pool_shared PUBLIC ${perf_include})

install (TARGETS concord_client_pool_shared DESTINATION lib${LIB_SUFFIX})

install (TARGETS concord_client_pool DESTINATION lib${LIB_SUFFIX})
