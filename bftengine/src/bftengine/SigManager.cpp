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

#include "SigManager.hpp"
#include "Crypto.hpp"
#include "assertUtils.hpp"

namespace bftEngine {
namespace impl {

SigManager* SigManager::instance_{nullptr};

SigManager::SigManager(PrincipalId myId,
                       const Key& mySigPrivateKey,
                       const std::vector<Key>& publickeys,
                       const std::map<PrincipalId, KeyIndex>& publicKeysMapping)
    : myId_(myId) {
  std::map<KeyIndex, RSAVerifier*> publicKeyToVerifier;
  mySigner_ = new RSASigner(mySigPrivateKey.c_str());
  size_t numPublickeys = publickeys.size();
  ConcordAssert(publicKeysMapping.size() >= numPublickeys);
  ConcordAssert(numPublickeys > 0);

  for (const auto& p : publicKeysMapping) {
    ConcordAssert(verifiers_.count(p.first) == 0);
    LOG_INFO(GL, KVLOG(p.second));
    LOG_INFO(GL, KVLOG(numPublickeys));
    ConcordAssert(p.second < numPublickeys);

    auto iter = publicKeyToVerifier.find(p.second);
    if (iter == publicKeyToVerifier.end()) {
      verifiers_[p.first] = new RSAVerifier(publickeys[p.second].c_str());
      publicKeyToVerifier[p.second] = verifiers_[p.first];
    } else
      verifiers_[p.first] = iter->second;

    ConcordAssert(p.first != myId);
  }
}

SigManager::~SigManager() {
  if (instance_) {
    delete mySigner_;
    for (std::pair<ReplicaId, RSAVerifier*> v : verifiers_) delete v.second;
    instance_ = nullptr;
  }
}

uint16_t SigManager::getSigLength(ReplicaId replicaId) const {
  if (replicaId == myId_) {
    return (uint16_t)mySigner_->signatureLength();
  } else {
    auto pos = verifiers_.find(replicaId);
    ConcordAssert(pos != verifiers_.end());

    RSAVerifier* verifier = pos->second;

    return (uint16_t)verifier->signatureLength();
  }
}

bool SigManager::verifySig(
    ReplicaId replicaId, const char* data, size_t dataLength, const char* sig, uint16_t sigLength) const {
  auto pos = verifiers_.find(replicaId);
  ConcordAssert(pos != verifiers_.end());

  RSAVerifier* verifier = pos->second;

  bool res = verifier->verify(data, dataLength, sig, sigLength);

  return res;
}

void SigManager::sign(const char* data, size_t dataLength, char* outSig, uint16_t outSigLength) const {
  size_t actualSigSize = 0;
  mySigner_->sign(data, dataLength, outSig, outSigLength, actualSigSize);
  ConcordAssert(outSigLength == actualSigSize);
}

uint16_t SigManager::getMySigLength() const { return (uint16_t)mySigner_->signatureLength(); }

}  // namespace impl
}  // namespace bftEngine
