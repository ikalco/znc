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

#include <znc/IRCNetwork.h>
#include <znc/Modules.h>

class CSocksMod : public CModule {
  public:
    MODCONSTRUCTOR(CSocksMod) {}

    ~CSocksMod() override {
        if (GetNetwork() && GetNetwork()->HasProxy()) {
            GetNetwork()->ClearProxy();
        }
    }

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        if (!SetProxy(sArgs, sMessage)) {
            return false;
        }

        PutModule(sMessage);
        return true;
    }

    void OnModCommand(const CString& sCommand) override {
        const CString& sCmd = sCommand.Token(0);

        if (sCmd.Equals("SET")) {
            CString sArgs = sCommand.Token(1, true);
            CString sMessage;
            if (SetProxy(sArgs, sMessage)) {
                PutModule(sMessage);
            } else {
                PutModule(t_f("Error: {1}")(sMessage));
            }
        } else if (sCmd.Equals("CLEAR")) {
            if (GetNetwork()->HasProxy()) {
                GetNetwork()->ClearProxy();
                PutModule(t_s("SOCKS proxy cleared"));
            } else {
                PutModule(t_s("No SOCKS proxy is configured"));
            }
        } else if (sCmd.Equals("SHOW")) {
            ShowProxy();
        } else if (sCmd.Equals("HELP")) {
            ShowHelp();
        } else {
            PutModule(t_s("Unknown command. Use HELP."));
        }
    }

  private:
    bool SetProxy(const CString& sArgs, CString& sMessage) {
        const CString& sHost = sArgs.Token(0);
        const CString& sPort = sArgs.Token(1);
        CString sType = sArgs.Token(2);

        if (sHost.empty() || sPort.empty()) {
            sMessage =
                t_s("Usage: SET <host> <port> [socks5|socks4a]");
            return false;
        }

        const unsigned short uPort = sPort.ToUShort();
        if (uPort == 0) {
            sMessage = t_s("Invalid proxy port");
            return false;
        }

        if (sType.empty()) {
            sType = "socks5";
        }
        sType.MakeLower();
        if (sType != "socks5" && sType != "socks4a") {
            sMessage = t_s("Invalid proxy type. Use socks5 or socks4a");
            return false;
        }

        GetNetwork()->SetProxy(sHost, uPort, sType);
        sMessage = t_f("SOCKS proxy set to {1}:{2} ({3})")(
            sHost, CString(uPort), sType);
        return true;
    }

    void ShowProxy() {
        if (!GetNetwork()->HasProxy()) {
            PutModule(t_s("No SOCKS proxy is configured"));
            return;
        }

        PutModule(t_f("Current SOCKS proxy: {1}:{2} ({3})")(
            GetNetwork()->GetProxyHost(),
            CString(GetNetwork()->GetProxyPort()),
            GetNetwork()->GetProxyType()));
    }

    void ShowHelp() {
        PutModule(t_s("Commands:"));
        PutModule(t_s("  SET <host> <port> [socks5|socks4a]"));
        PutModule(t_s("  CLEAR"));
        PutModule(t_s("  SHOW"));
        PutModule(t_s("  HELP"));
    }
};

MODULEDEFS(CSocksMod, "Route network traffic through a SOCKS4a/SOCKS5 proxy")
