import LessPassFingerprint from "lesspass-fingerprint";
import { calcEntropy } from "lesspass-entropy";
import { renderPassword } from "lesspass-render-password";

interface Options {
  uppercase: boolean;
  lowercase: boolean;
  digits: boolean;
  symbols: boolean;
  length: number;
  counter: number;
}

interface Profile extends Options {
  site: string;
  login: string;
}

export function generatePassword(profile: Profile, masterPassword: string) {
  const site = profile.site;
  const login = profile.login;
  const length = profile.length;
  const counter = profile.counter;
  const lowercase = profile.lowercase;
  const uppercase = profile.uppercase;
  const digits = profile.digits;
  const symbols = profile.symbols;

  return calcEntropy(
    {
      site,
      login,
      counter,
    },
    masterPassword
  ).then((entropy) => {
    const options = {
      length,
      lowercase,
      uppercase,
      digits,
      symbols,
    };
    const generatedPassword = renderPassword(entropy, options);
    return Promise.resolve(generatedPassword);
  });
}

export function createFingerprint(key:string) {
  return LessPassFingerprint.createHmac("sha256", key).then((hmac) => {
    const fingerprint = LessPassFingerprint.createFingerprint(hmac);
    return Promise.resolve(fingerprint);
  });
}

export default {
  generatePassword,
  createFingerprint,
};
