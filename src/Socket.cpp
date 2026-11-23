/*
 * Copyright (C) 2004-2026 ZNC, see the NOTICE file for details.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <random>

#include <znc/Socket.h>
#include <znc/User.h>
#include <znc/IRCNetwork.h>
#include <znc/SSLVerifyHost.h>
#include <znc/znc.h>
#include <signal.h>

#ifdef HAVE_ICU
#include <unicode/ucnv_cb.h>
#endif

#ifdef HAVE_LIBSSL
// Copypasted from
// https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29
// at 2024-02-08 (version 5.7)
static CString ZNC_DefaultCipher() {
    // This is TLS1.2 only, because TLS1.3 ciphers are probably not configurable here yet
    return "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
           "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
           "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
           "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305";
}
#endif

CZNCSock::CZNCSock(int timeout)
    : Csock(timeout),
      m_sHostToVerifySSL(""),
      m_ssTrustedFingerprints(),
      m_ssCertVerificationErrors(),
      m_uProxyPort(0),
      m_uProxyTargetPort(0) {
#ifdef HAVE_LIBSSL
    DisableSSLCompression();
    FollowSSLCipherServerPreference();
    DisableSSLProtocols(CZNC::Get().GetDisabledSSLProtocols());
    CString sCipher = CZNC::Get().GetSSLCiphers();
    if (sCipher.empty()) {
        sCipher = ZNC_DefaultCipher();
    }
    SetCipher(sCipher);
#endif
}

CZNCSock::CZNCSock(const CString& sHost, u_short port, int timeout)
    : Csock(sHost, port, timeout),
      m_sHostToVerifySSL(""),
      m_ssTrustedFingerprints(),
      m_ssCertVerificationErrors(),
      m_uProxyPort(0),
      m_uProxyTargetPort(0) {
#ifdef HAVE_LIBSSL
    DisableSSLCompression();
    FollowSSLCipherServerPreference();
    DisableSSLProtocols(CZNC::Get().GetDisabledSSLProtocols());
#endif
}

unsigned int CSockManager::GetAnonConnectionCount(const CString& sIP) const {
    unsigned int ret = 0;

    for (const Csock* pSock : *this) {
        // Logged in CClients have "USR::<username>" as their sockname
        if (pSock->GetType() == Csock::INBOUND && pSock->GetRemoteIP() == sIP &&
            !pSock->GetSockName().StartsWith("USR::")) {
            ret++;
        }
    }

    DEBUG("There are [" << ret << "] clients from [" << sIP << "]");

    return ret;
}

int CZNCSock::ConvertAddress(const struct sockaddr_storage* pAddr,
                             socklen_t iAddrLen, CString& sIP,
                             u_short* piPort) const {
    int ret = Csock::ConvertAddress(pAddr, iAddrLen, sIP, piPort);
    if (ret == 0) sIP.TrimPrefix("::ffff:");
    return ret;
}

#ifdef HAVE_LIBSSL
int CZNCSock::VerifyPeerCertificate(int iPreVerify, X509_STORE_CTX* pStoreCTX) {
    if (iPreVerify == 0) {
        m_ssCertVerificationErrors.insert(
            X509_verify_cert_error_string(X509_STORE_CTX_get_error(pStoreCTX)));
    }
    return 1;
}

void CZNCSock::SSLHandShakeFinished() {
    X509* pCert = GetX509();
    if (!CheckSSLCert(pCert)) {
        Close();
    }
    X509_free(pCert);
}

bool CZNCSock::CheckSSLCert(X509* pCert) {
    if (GetType() != ETConn::OUTBOUND) {
        return true;
    }

    if (!pCert) {
        DEBUG(GetSockName() + ": No cert");
        CallSockError(errnoBadSSLCert, "Anonymous SSL cert is not allowed");
        return false;
    }
    if (GetTrustAllCerts()) {
        DEBUG(GetSockName() + ": Verification disabled, trusting all.");
        return true;
    }
    CString sHostVerifyError;
    if (!ZNC_SSLVerifyHost(m_sHostToVerifySSL, pCert, sHostVerifyError)) {
        m_ssCertVerificationErrors.insert(sHostVerifyError);
    }
    if (GetTrustPKI() && m_ssCertVerificationErrors.empty()) {
        DEBUG(GetSockName() + ": Good cert (PKI valid)");
        return true;
    }
    CString sFP = GetSSLPeerFingerprint(pCert);
    if (m_ssTrustedFingerprints.count(sFP) != 0) {
        DEBUG(GetSockName() + ": Cert explicitly trusted by user: " << sFP);
        return true;
    }
    DEBUG(GetSockName() + ": Bad cert");
    CString sErrorMsg = "Invalid SSL certificate: ";
    sErrorMsg += CString(", ").Join(begin(m_ssCertVerificationErrors),
                                    end(m_ssCertVerificationErrors));
    SSLCertError(pCert);
    CallSockError(errnoBadSSLCert, sErrorMsg);
    return false;
}

bool CZNCSock::SNIConfigureClient(CString& sHostname) {
    sHostname = m_sHostToVerifySSL;
    return true;
}

CString CZNCSock::GetSSLPeerFingerprint(X509* pCert) const {
    // Csocket's version returns insecure SHA-1
    // This one is SHA-256
    const EVP_MD* evp = EVP_sha256();
    bool bOwned = false;
    if (!pCert) {
        pCert = GetX509();
        bOwned = true;
    }
    if (!pCert) {
        DEBUG(GetSockName() + ": GetSSLPeerFingerprint: Anonymous cert");
        return "";
    }
    unsigned char buf[256 / 8];
    unsigned int _32 = 256 / 8;
    int iSuccess = X509_digest(pCert, evp, buf, &_32);
    if (bOwned) {
        X509_free(pCert);
    }
    if (!iSuccess) {
        DEBUG(GetSockName() + ": GetSSLPeerFingerprint: Couldn't find digest");
        return "";
    }
    return CString(reinterpret_cast<const char*>(buf), sizeof buf)
        .Escape_n(CString::EASCII, CString::EHEXCOLON);
}
#endif

void CZNCSock::SetEncoding(const CString& sEncoding) {
#ifdef HAVE_ICU
    Csock::SetEncoding(CZNC::Get().FixupEncoding(sEncoding));
#endif
}

void CZNCSock::SetProxy(const CString& sHostname, unsigned short uPort,
                        const CString& sType) {
    m_sProxyHostname = sHostname;
    m_uProxyPort = uPort;
    m_sProxyType = sType;
    m_sProxyType.MakeLower();
    if (m_sProxyType != "socks5" && m_sProxyType != "socks4a") {
        m_sProxyType = "socks5";
    }
}

void CZNCSock::SetProxyTarget(const CString& sHostname, unsigned short uPort,
                              bool bSSL) {
    m_sProxyTargetHostname = sHostname;
    m_uProxyTargetPort = uPort;
    m_bProxyTargetSSL = bSSL;
    m_iProxyState = 0;
    m_bProxyConnected = false;
    m_sProxyBuffer.clear();
}

void CZNCSock::ProxyError(const CString& sError) {
    errno = ECONNREFUSED;
    SetIsConnected(false);
    SetConState(Csock::CST_CONNECTWAIT);
    CallSockError(ECONNREFUSED, sError);
    Close();
}

CString CZNCSock::BuildProxyRequest() const {
    CString sRequest;

    if (m_sProxyType.Equals("socks4a")) {
        sRequest.append(1, '\x04');
        sRequest.append(1, '\x01');
        sRequest.append(1, static_cast<char>((m_uProxyTargetPort >> 8) & 0xff));
        sRequest.append(1, static_cast<char>(m_uProxyTargetPort & 0xff));
        // 0.0.0.1 tells the SOCKS4 server that a SOCKS4a domain name follows.
        sRequest.append(1, '\x00');
        sRequest.append(1, '\x00');
        sRequest.append(1, '\x00');
        sRequest.append(1, '\x01');
        // Empty user id.
        sRequest.append(1, '\x00');
        sRequest.append(m_sProxyTargetHostname);
        sRequest.append(1, '\x00');
    } else {
        // SOCKS5 method negotiation: no authentication required.
        sRequest.append(1, '\x05');
        sRequest.append(1, '\x01');
        sRequest.append(1, '\x00');
    }

    return sRequest;
}

CString CZNCSock::BuildSocks5ConnectRequest() const {
    CString sRequest;
    sRequest.append(1, '\x05');
    sRequest.append(1, '\x01');
    sRequest.append(1, '\x00');
    sRequest.append(1, '\x03');

    size_t uHostLen = m_sProxyTargetHostname.size();
    if (uHostLen > 255) {
        uHostLen = 255;
    }
    sRequest.append(1, static_cast<char>(uHostLen));
    sRequest.append(m_sProxyTargetHostname.data(), uHostLen);
    sRequest.append(1, static_cast<char>((m_uProxyTargetPort >> 8) & 0xff));
    sRequest.append(1, static_cast<char>(m_uProxyTargetPort & 0xff));

    return sRequest;
}

cs_ssize_t CZNCSock::Read(char* data, size_t len) {
    if (!HasProxy() || m_bProxyConnected) {
        return Csock::Read(data, len);
    }

    // The TCP connection to the proxy is already established.  Mark it as
    // connected now, so that Csock does not treat READ_EAGAIN from the proxy
    // handshake as the TCP connect completion and call Connected() too early.
    if (!IsConnected()) {
        SetIsConnected(true);
    }

    while (true) {
        if (m_iProxyState == 0) {
            if (!Write(BuildProxyRequest())) {
                ProxyError(t_s("SOCKS proxy connection failed"));
                return Csock::READ_ERR;
            }
            m_iProxyState = 1;
        }

        char szBuffer[1024];
        cs_ssize_t iBytes = Csock::Read(szBuffer, sizeof(szBuffer));
        if (iBytes <= 0) {
            return iBytes;
        }
        m_sProxyBuffer.append(szBuffer, iBytes);

        if (m_sProxyType.Equals("socks5")) {
            if (m_iProxyState == 1) {
                if (m_sProxyBuffer.size() < 2) {
                    return Csock::READ_EAGAIN;
                }

                const unsigned char uVersion =
                    static_cast<unsigned char>(m_sProxyBuffer[0]);
                const unsigned char uMethod =
                    static_cast<unsigned char>(m_sProxyBuffer[1]);
                m_sProxyBuffer.erase(0, 2);

                if (uVersion != 0x05 || uMethod != 0x00) {
                    ProxyError(t_s("SOCKS5 proxy rejected the selected authentication method"));
                    return Csock::READ_ERR;
                }

                if (!Write(BuildSocks5ConnectRequest())) {
                    ProxyError(t_s("SOCKS proxy connection failed"));
                    return Csock::READ_ERR;
                }
                m_iProxyState = 2;
                continue;
            }

            // m_iProxyState == 2: parse the SOCKS5 connect reply.
            if (m_sProxyBuffer.size() < 4) {
                return Csock::READ_EAGAIN;
            }

            const unsigned char uVersion =
                static_cast<unsigned char>(m_sProxyBuffer[0]);
            const unsigned char uReply =
                static_cast<unsigned char>(m_sProxyBuffer[1]);
            const unsigned char uAtyp =
                static_cast<unsigned char>(m_sProxyBuffer[3]);

            size_t uAddrLen = 0;
            if (uAtyp == 0x01) {
                uAddrLen = 4;
            } else if (uAtyp == 0x04) {
                uAddrLen = 16;
            } else if (uAtyp == 0x03) {
                if (m_sProxyBuffer.size() < 5) {
                    return Csock::READ_EAGAIN;
                }
                uAddrLen = static_cast<unsigned char>(m_sProxyBuffer[4]);
            } else {
                ProxyError(t_s("SOCKS5 proxy returned an invalid address type"));
                return Csock::READ_ERR;
            }

            const size_t uReplyLen = 4 + (uAtyp == 0x03 ? 1 + uAddrLen : uAddrLen) + 2;
            if (m_sProxyBuffer.size() < uReplyLen) {
                return Csock::READ_EAGAIN;
            }
            m_sProxyBuffer.erase(0, uReplyLen);

            if (uVersion != 0x05 || uReply != 0x00) {
                ProxyError(t_s("SOCKS5 proxy could not connect to the target server"));
                return Csock::READ_ERR;
            }
            m_bProxyConnected = true;
        } else {
            // SOCKS4a reply: 8 bytes, 0x00 0x5A followed by port/address.
            if (m_sProxyBuffer.size() < 8) {
                return Csock::READ_EAGAIN;
            }

            const unsigned char uVersion =
                static_cast<unsigned char>(m_sProxyBuffer[0]);
            const unsigned char uStatus =
                static_cast<unsigned char>(m_sProxyBuffer[1]);
            m_sProxyBuffer.erase(0, 8);

            if (uVersion != 0x00 || uStatus != 0x5A) {
                ProxyError(t_s("SOCKS4a proxy could not connect to the target server"));
                return Csock::READ_ERR;
            }
            m_bProxyConnected = true;
        }

        if (m_bProxyConnected) {
            break;
        }
    }

    // The SOCKS handshake is complete.  Now set up the real connection state.
    // For SSL targets the TLS handshake starts after this, exactly as it would
    // for a direct connection.
    SetSSL(m_bProxyTargetSSL);
    SetConState(m_bProxyTargetSSL ? Csock::CST_CONNECTSSL : Csock::CST_OK);
    Connected();

    if (!m_sProxyBuffer.empty()) {
        const size_t uCopy = std::min(m_sProxyBuffer.size(), len);
        memcpy(data, m_sProxyBuffer.data(), uCopy);
        m_sProxyBuffer.erase(0, uCopy);
        return static_cast<cs_ssize_t>(uCopy);
    }

    return Csock::READ_EAGAIN;
}

#ifdef HAVE_PTHREAD
class CSockManager::CThreadMonitorFD : public CSMonitorFD {
  public:
    CThreadMonitorFD() { Add(CThreadPool::Get().getReadFD(), ECT_Read); }

    bool FDsThatTriggered(const std::map<int, short>& miiReadyFds) override {
        if (miiReadyFds.find(CThreadPool::Get().getReadFD())->second) {
            CThreadPool::Get().handlePipeReadable();
        }
        return true;
    }
};
#endif

#ifdef HAVE_THREADED_DNS
void CSockManager::CDNSJob::runThread() {
    int iCount = 0;
    while (true) {
        addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_ADDRCONFIG;
        iRes = getaddrinfo(sHostname.c_str(), nullptr, &hints, &aiResult);
        if (EAGAIN != iRes) {
            break;
        }

        iCount++;
        if (iCount > 5) {
            iRes = ETIMEDOUT;
            break;
        }
        sleep(5);  // wait 5 seconds before next try
    }
}

void CSockManager::CDNSJob::runMain() {
    if (0 != this->iRes) {
        DEBUG("Error in threaded DNS: " << gai_strerror(this->iRes) << " while trying to resolve " << this->sHostname);
        if (this->aiResult) {
            DEBUG("And aiResult is not nullptr...");
        }
        // just for case. Maybe to call freeaddrinfo()?
        this->aiResult = nullptr;
    }
    pManager->SetTDNSThreadFinished(this->task, this->bBind, this->aiResult);
}

void CSockManager::StartTDNSThread(TDNSTask* task, bool bBind) {
    CString sHostname = bBind ? task->sBindhost : task->sHostname;
    CDNSJob* arg = new CDNSJob;
    arg->sHostname = sHostname;
    arg->task = task;
    arg->bBind = bBind;
    arg->pManager = this;

    CThreadPool::Get().addJob(arg);
}

static CString RandomFromSet(const SCString& sSet,
                             std::default_random_engine& gen) {
    std::uniform_int_distribution<> distr(0, sSet.size() - 1);
    auto it = sSet.cbegin();
    std::advance(it, distr(gen));
    return *it;
}

static std::tuple<CString, bool> RandomFrom2SetsWithBias(
    const SCString& ss4, const SCString& ss6, std::default_random_engine& gen) {
    // It's not quite what RFC says how to choose between IPv4 and IPv6, but
    // proper way is harder to implement.
    // It would require to maintain some state between Csock objects.
    bool bUseIPv6;
    if (ss4.empty()) {
        bUseIPv6 = true;
    } else if (ss6.empty()) {
        bUseIPv6 = false;
    } else {
        // Let's prefer IPv6 :)
        std::discrete_distribution<> d({2, 3});
        bUseIPv6 = d(gen);
    }
    const SCString& sSet = bUseIPv6 ? ss6 : ss4;
    return std::make_tuple(RandomFromSet(sSet, gen), bUseIPv6);
}

void CSockManager::SetTDNSThreadFinished(TDNSTask* task, bool bBind,
                                         addrinfo* aiResult) {
    if (bBind) {
        task->aiBind = aiResult;
        task->bDoneBind = true;
    } else {
        task->aiTarget = aiResult;
        task->bDoneTarget = true;
    }

    // Now that something is done, check if everything we needed is done
    if (!task->bDoneBind || !task->bDoneTarget) {
        return;
    }

    // All needed DNS is done, now collect the results
    SCString ssTargets4;
    SCString ssTargets6;
    for (addrinfo* ai = task->aiTarget; ai; ai = ai->ai_next) {
        char s[INET6_ADDRSTRLEN] = {};
        getnameinfo(ai->ai_addr, ai->ai_addrlen, s, sizeof(s), nullptr, 0,
                    NI_NUMERICHOST);
        switch (ai->ai_family) {
            case AF_INET:
                ssTargets4.insert(s);
                break;
#ifdef HAVE_IPV6
            case AF_INET6:
                ssTargets6.insert(s);
                break;
#endif
        }
    }
    SCString ssBinds4;
    SCString ssBinds6;
    for (addrinfo* ai = task->aiBind; ai; ai = ai->ai_next) {
        char s[INET6_ADDRSTRLEN] = {};
        getnameinfo(ai->ai_addr, ai->ai_addrlen, s, sizeof(s), nullptr, 0,
                    NI_NUMERICHOST);
        switch (ai->ai_family) {
            case AF_INET:
                ssBinds4.insert(s);
                break;
#ifdef HAVE_IPV6
            case AF_INET6:
                ssBinds6.insert(s);
                break;
#endif
        }
    }
    if (task->aiTarget) freeaddrinfo(task->aiTarget);
    if (task->aiBind) freeaddrinfo(task->aiBind);

    CString sBindhost;
    CString sTargetHost;
    std::random_device rd;
    std::default_random_engine gen(rd());

    try {
        if (ssTargets4.empty() && ssTargets6.empty()) {
            throw t_s("Can't resolve server hostname");
        } else if (task->sBindhost.empty()) {
            // Choose random target
            std::tie(sTargetHost, std::ignore) =
                RandomFrom2SetsWithBias(ssTargets4, ssTargets6, gen);
        } else if (ssBinds4.empty() && ssBinds6.empty()) {
            throw t_s(
                "Can't resolve bind hostname. Try /znc ClearBindHost and /znc "
                "ClearUserBindHost");
        } else if (ssBinds4.empty()) {
            if (ssTargets6.empty()) {
                throw t_s(
                    "Server address is IPv4-only, but bindhost is IPv6-only");
            } else {
                // Choose random target and bindhost from IPv6-only sets
                sTargetHost = RandomFromSet(ssTargets6, gen);
                sBindhost = RandomFromSet(ssBinds6, gen);
            }
        } else if (ssBinds6.empty()) {
            if (ssTargets4.empty()) {
                throw t_s(
                    "Server address is IPv6-only, but bindhost is IPv4-only");
            } else {
                // Choose random target and bindhost from IPv4-only sets
                sTargetHost = RandomFromSet(ssTargets4, gen);
                sBindhost = RandomFromSet(ssBinds4, gen);
            }
        } else {
            // Choose random target
            bool bUseIPv6;
            std::tie(sTargetHost, bUseIPv6) =
                RandomFrom2SetsWithBias(ssTargets4, ssTargets6, gen);
            // Choose random bindhost matching chosen target
            const SCString& ssBinds = bUseIPv6 ? ssBinds6 : ssBinds4;
            sBindhost = RandomFromSet(ssBinds, gen);
        }

        DEBUG("TDNS: " << task->sSockName << ", connecting to [" << sTargetHost
                       << "] using bindhost [" << sBindhost << "]");
        FinishConnect(sTargetHost, task->iPort, task->sSockName, task->iTimeout,
                      task->bSSL, sBindhost, task->pcSock);
    } catch (const CString& s) {
        DEBUG(task->sSockName << ", dns resolving error: " << s);
        task->pcSock->SetSockName(task->sSockName);
        task->pcSock->SockError(-1, s);
        delete task->pcSock;
    }

    delete task;
}
#endif /* HAVE_THREADED_DNS */

CSockManager::CSockManager() {
#ifdef HAVE_PTHREAD
    MonitorFD(new CThreadMonitorFD());
#endif
}

CSockManager::~CSockManager() {}

void CSockManager::Connect(const CString& sHostname, u_short iPort,
                           const CString& sSockName, int iTimeout, bool bSSL,
                           const CString& sBindHost, CZNCSock* pcSock) {
    m_InFlightDnsSockets[pcSock] = false;

    CString sConnectHostname = sHostname;
    u_short uConnectPort = iPort;
    if (pcSock) {
        pcSock->SetHostToVerifySSL(sHostname);
        if (pcSock->HasProxy()) {
            pcSock->SetProxyTarget(sHostname, iPort, bSSL);
            sConnectHostname = pcSock->GetProxyHostname();
            uConnectPort = pcSock->GetProxyPort();
        }
    }

#ifdef HAVE_THREADED_DNS
    DEBUG("TDNS: initiating resolving of [" << sConnectHostname
                                            << "] and bindhost [" << sBindHost
                                            << "]");
    TDNSTask* task = new TDNSTask;
    task->sHostname = sConnectHostname;
    task->iPort = uConnectPort;
    task->sSockName = sSockName;
    task->iTimeout = iTimeout;
    task->bSSL = bSSL;
    task->sBindhost = sBindHost;
    task->pcSock = pcSock;
    if (sBindHost.empty()) {
        task->bDoneBind = true;
    } else {
        StartTDNSThread(task, true);
    }
    StartTDNSThread(task, false);
#else /* HAVE_THREADED_DNS */
    // Just let Csocket handle DNS itself
    FinishConnect(sConnectHostname, uConnectPort, sSockName, iTimeout, bSSL,
                  sBindHost, pcSock);
#endif
}

void CSockManager::FinishConnect(const CString& sHostname, u_short iPort,
                                 const CString& sSockName, int iTimeout,
                                 bool bSSL, const CString& sBindHost,
                                 CZNCSock* pcSock) {
    auto it = m_InFlightDnsSockets.find(pcSock);
    if (it != m_InFlightDnsSockets.end()) {
        bool bSocketDeletedAlready = it->second;
        m_InFlightDnsSockets.erase(it);
        if (bSocketDeletedAlready) {
            DEBUG("TDNS: Socket ["
                  << sSockName
                  << "] is deleted already, not proceeding with connection");
            return;
        }
    } else {
        // impossible
    }

    const bool bProxy = pcSock && pcSock->HasProxy();

    CSConnection C(sHostname, iPort, iTimeout);

    C.SetSockName(sSockName);
    // When a SOCKS proxy is used the TCP connection to the proxy itself is
    // always plaintext.  If the target connection is SSL, CZNCSock starts
    // the TLS handshake after the SOCKS handshake has completed.
    C.SetIsSSL(bSSL && !bProxy);
    C.SetBindHost(sBindHost);
#ifdef HAVE_LIBSSL
    CString sCipher = CZNC::Get().GetSSLCiphers();
    if (sCipher.empty()) {
        sCipher = ZNC_DefaultCipher();
    }
    C.SetCipher(sCipher);
    if (bProxy && bSSL) {
        pcSock->SetCipher(sCipher);
    }
#endif

    TSocketManager<CZNCSock>::Connect(C, pcSock);
}

void CSockManager::DelSockByAddr(Csock* pcSock) {
    auto it = m_InFlightDnsSockets.find(pcSock);
    if (it != m_InFlightDnsSockets.end()) {
        // The socket is resolving its DNS. When that finishes, let it silently
        // die without crash.
        it->second = true;
    }
    TSocketManager<CZNCSock>::DelSockByAddr(pcSock);
}

/////////////////// CSocket ///////////////////
CSocket::CSocket(CModule* pModule) : CZNCSock(), m_pModule(pModule) {
    if (m_pModule) m_pModule->AddSocket(this);
    EnableReadLine();
    SetMaxBufferThreshold(10240);
}

CSocket::CSocket(CModule* pModule, const CString& sHostname,
                 unsigned short uPort, int iTimeout)
    : CZNCSock(sHostname, uPort, iTimeout), m_pModule(pModule) {
    if (m_pModule) m_pModule->AddSocket(this);
    EnableReadLine();
    SetMaxBufferThreshold(10240);
}

CSocket::~CSocket() {
    CUser* pUser = nullptr;
    CIRCNetwork* pNetwork = nullptr;

    // CWebSock could cause us to have a nullptr pointer here
    if (m_pModule) {
        pUser = m_pModule->GetUser();
        pNetwork = m_pModule->GetNetwork();
        m_pModule->UnlinkSocket(this);
    }

    if (pNetwork && m_pModule &&
        (m_pModule->GetType() == CModInfo::NetworkModule)) {
        pNetwork->AddBytesWritten(GetBytesWritten());
        pNetwork->AddBytesRead(GetBytesRead());
    } else if (pUser && m_pModule &&
               (m_pModule->GetType() == CModInfo::UserModule)) {
        pUser->AddBytesWritten(GetBytesWritten());
        pUser->AddBytesRead(GetBytesRead());
    } else {
        CZNC::Get().AddBytesWritten(GetBytesWritten());
        CZNC::Get().AddBytesRead(GetBytesRead());
    }
}

void CSocket::ReachedMaxBuffer() {
    DEBUG(GetSockName() << " == ReachedMaxBuffer()");
    if (m_pModule)
        m_pModule->PutModule(
            t_s("Some socket reached its max buffer limit and was closed!"));
    Close();
}

void CSocket::SockError(int iErrno, const CString& sDescription) {
    DEBUG(GetSockName() << " == SockError(" << sDescription << ", "
                        << strerror(iErrno) << ")");
    if (iErrno == EMFILE) {
        // We have too many open fds, this can cause a busy loop.
        Close();
    }
}

bool CSocket::ConnectionFrom(const CString& sHost, unsigned short uPort) {
    return CZNC::Get().AllowConnectionFrom(sHost);
}

bool CSocket::Connect(const CString& sHostname, unsigned short uPort, bool bSSL,
                      unsigned int uTimeout) {
    if (!m_pModule) {
        DEBUG(
            "ERROR: CSocket::Connect called on instance without m_pModule "
            "handle!");
        return false;
    }

    CUser* pUser = m_pModule->GetUser();
    CString sBindHost;

    if (pUser) {
        sBindHost = pUser->GetBindHost();
        CIRCNetwork* pNetwork = m_pModule->GetNetwork();
        if (pNetwork) {
            sBindHost = pNetwork->GetBindHost();
            if (pNetwork->HasProxy()) {
                SetProxy(pNetwork->GetProxyHost(), pNetwork->GetProxyPort(),
                         pNetwork->GetProxyType());
            } else {
                ClearProxy();
            }
        }
    }

    CString sSockName = ConstructSockName("C");
    m_pModule->GetManager()->Connect(sHostname, uPort, sSockName, uTimeout,
                                     bSSL, sBindHost, this);
    return true;
}

bool CSocket::Listen(unsigned short uPort, bool bSSL, unsigned int uTimeout) {
    if (!m_pModule) {
        DEBUG(
            "ERROR: CSocket::Listen called on instance without m_pModule "
            "handle!");
        return false;
    }

    CString sSockName = ConstructSockName("L");
    return m_pModule->GetManager()->ListenAll(uPort, sSockName, bSSL, SOMAXCONN,
                                              this);
}

bool CSocket::ListenUnix(const CString& sPath) {
    if (!m_pModule) {
        DEBUG(
            "ERROR: CSocket::Listen called on instance without m_pModule "
            "handle!");
        return false;
    }

    CString sSockName = ConstructSockName("LU");
    return m_pModule->GetManager()->ListenUnix(sSockName, sPath, this);
}

bool CSocket::ConnectUnix(const CString& sPath) {
    if (!m_pModule) {
        DEBUG(
            "ERROR: CSocket::Listen called on instance without m_pModule "
            "handle!");
        return false;
    }

    CString sSockName = ConstructSockName("CU");
    return m_pModule->GetManager()->ConnectUnix(sSockName, sPath, this);
}

CString CSocket::ConstructSockName(const CString& sPart) const {
    CString sSockName = GetSockName();
    if (!sSockName.empty()) return sSockName;

    sSockName = "MOD::" + sPart + "::" + m_pModule->GetModName();

    if (CUser* pUser = m_pModule->GetUser()) {
        sSockName += "::" + pUser->GetUsername();
        if (CIRCNetwork* pNetwork = m_pModule->GetNetwork()) {
            sSockName += "::" + pNetwork->GetName();
        }
    }
    return sSockName;
}

CModule* CSocket::GetModule() const { return m_pModule; }
/////////////////// !CSocket ///////////////////

#ifdef HAVE_ICU
void CIRCSocket::IcuExtToUCallback(UConverterToUnicodeArgs* toArgs,
                                   const char* codeUnits, int32_t length,
                                   UConverterCallbackReason reason,
                                   UErrorCode* err) {
    // From http://www.mirc.com/colors.html
    // The Control+O key combination in mIRC inserts ascii character 15,
    // which turns off all previous attributes, including color, bold,
    // underline, and italics.
    //
    // \x02 bold
    // \x03 mIRC-compatible color
    // \x04 RRGGBB color
    // \x0F normal/reset (turn off bold, colors, etc.)
    // \x12 reverse (weechat)
    // \x16 reverse (mirc, kvirc)
    // \x1D italic
    // \x1F underline
    // Also see http://www.visualirc.net/tech-attrs.php
    //
    // Keep in sync with CUser::AddTimestamp and CIRCSocket::IcuExtFromUCallback
    static const std::set<char> scAllowedChars = {
        '\x02', '\x03', '\x04', '\x0F', '\x12', '\x16', '\x1D', '\x1F'};
    if (reason == UCNV_ILLEGAL && length == 1 &&
        scAllowedChars.count(*codeUnits)) {
        *err = U_ZERO_ERROR;
        UChar c = *codeUnits;
        ucnv_cbToUWriteUChars(toArgs, &c, 1, 0, err);
        return;
    }
    Csock::IcuExtToUCallback(toArgs, codeUnits, length, reason, err);
}

void CIRCSocket::IcuExtFromUCallback(UConverterFromUnicodeArgs* fromArgs,
                                     const UChar* codeUnits, int32_t length,
                                     UChar32 codePoint,
                                     UConverterCallbackReason reason,
                                     UErrorCode* err) {
    // See comment in CIRCSocket::IcuExtToUCallback
    static const std::set<UChar32> scAllowedChars = {0x02, 0x03, 0x04, 0x0F,
                                                     0x12, 0x16, 0x1D, 0x1F};
    if (reason == UCNV_ILLEGAL && scAllowedChars.count(codePoint)) {
        *err = U_ZERO_ERROR;
        char c = codePoint;
        ucnv_cbFromUWriteBytes(fromArgs, &c, 1, 0, err);
        return;
    }
    Csock::IcuExtFromUCallback(fromArgs, codeUnits, length, codePoint, reason,
                               err);
}
#endif


CString CSocket::t_s(const CString& sEnglish, const CString& sContext) const {
    return GetModule()->t_s(sEnglish, sContext);
}

CInlineFormatMessage CSocket::t_f(const CString& sEnglish,
                                  const CString& sContext) const {
    return GetModule()->t_f(sEnglish, sContext);
}

CInlineFormatMessage CSocket::t_p(const CString& sEnglish,
                                  const CString& sEnglishes, int iNum,
                                  const CString& sContext) const {
    return GetModule()->t_p(sEnglish, sEnglishes, iNum, sContext);
}

CDelayedTranslation CSocket::t_d(const CString& sEnglish,
                                 const CString& sContext) const {
    return GetModule()->t_d(sEnglish, sContext);
}
