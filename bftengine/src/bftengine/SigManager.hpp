// Concord
//
// Copyright (c) 2018 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License").  You may not use this product except in
// compliance with the Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright notices and license terms. Your use of
// these subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.

#pragma once
#include "PrimitiveTypes.hpp"
#include "assertUtils.hpp"

#include <utility>
#include <vector>
#include <map>
#include <string>
#include <memory>

// createSigManager should be used only for test purpose!
// namespace bftEngine::impl {
// class SigManager;
// }
// bftEngine::impl::SigManager* createSigManager(size_t, std::string&, std::set<std::pair<uint16_t, const
// std::string>>&);

namespace bftEngine {
namespace impl {

class RSASigner;
class RSAVerifier;

class SigManager {
 public:
  typedef std::string Key;
  typedef uint16_t KeyIndex;

  // use this function only for testing (Testing is a namespace)!
  // friend SigManager* ::createSigManager(size_t, std::string&, std::set<std::pair<uint16_t, const std::string>>&);

  static SigManager* getInstance() {
    ConcordAssertNE(instance_, nullptr);
    return instance_;
  }

  static SigManager* init(PrincipalId myId,
                          const Key& mySigPrivateKey,
                          const std::vector<Key>& publickeys,
                          const std::map<PrincipalId, KeyIndex>& publicKeysMapping) {
    ConcordAssertEQ(instance_, nullptr);
    instance_ = new SigManager(myId, mySigPrivateKey, publickeys, publicKeysMapping);
    return instance_;
  }

  ~SigManager();

  uint16_t getSigLength(PrincipalId replicaId) const;
  bool verifySig(PrincipalId replicaId, const char* data, size_t dataLength, const char* sig, uint16_t sigLength) const;
  void sign(const char* data, size_t dataLength, char* outSig, uint16_t outSigLength) const;
  uint16_t getMySigLength() const;

  SigManager(const SigManager&) = delete;
  SigManager& operator=(const SigManager&) = delete;
  SigManager(SigManager&&) = delete;
  SigManager& operator=(SigManager&&) = delete;

 protected:
  static SigManager* instance;
  const PrincipalId myId_;
  RSASigner* mySigner_;
  std::map<PrincipalId, RSAVerifier*> verifiers_;

  SigManager(PrincipalId myId,
             const Key& mySigPrivateKey,
             const std::vector<Key>& publickeys,
             const std::map<PrincipalId, KeyIndex>& publicKeysMapping);

  static SigManager* instance_;
};

}  // namespace impl
}  // namespace bftEngine
