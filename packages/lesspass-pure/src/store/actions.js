import Password from "../api/password";
import * as urlParser from "../services/url-parser";
import * as types from "./mutation-types";
import defaultPasswordProfile from "./defaultPassword";

export const saveDefaultOptions = ({ commit }, payload) => {
  commit(types.SET_DEFAULT_OPTIONS, payload);
};

export const loadPasswordProfile = ({ commit }, { site }) => {
  commit(types.LOAD_PASSWORD_PROFILE, { site });
};

export const getPasswordFromUrlQuery = ({ commit }, { query }) => {
  const password = urlParser.getPasswordFromUrlQuery(query);
  const expectedNbOfElements = Object.keys(defaultPasswordProfile).length;
  if (Object.keys(password).length === expectedNbOfElements) {
    commit(types.SET_PASSWORD, { password });
  }
};

export const savePassword = ({ commit }, payload) => {
  commit(types.SET_PASSWORD, payload);
};

export const resetPassword = ({ commit }) => {
  commit(types.RESET_PASSWORD);
};

export const setBaseURL = ({ commit }, { baseURL }) => {
  commit(types.SET_BASE_URL, { baseURL });
};

export const login = ({ commit }, { access, refresh }) => {
  commit(types.SET_TOKENS, { access_token: access, refresh_token: refresh });
  commit(types.LOGIN);
};

export const logout = ({ commit }) => {
  commit(types.LOGOUT);
  commit(types.RESET_PASSWORD);
};

export const getPasswords = ({ commit }) => {
  return Password.all().then(response => {
    const passwords = response.data.results;
    commit(types.SET_PASSWORDS, { passwords });
    return passwords;
  });
};

export const createPassword = ({ commit, state }) => {
  return Password.create(state.password, state).then(() =>
    getPasswords({ commit, state })
  );
};

export const updatePassword = ({ commit, state }) => {
  return Password.update(state.password, state).then(() =>
    getPasswords({ commit, state })
  );
};

export const deletePassword = ({ commit, state }, payload) => {
  Password.delete(payload, state).then(() => {
    commit(types.DELETE_PASSWORD, payload);
  });
};

export const displayMessage = ({ commit }, payload) => {
  commit(types.SET_MESSAGE, payload);
};

export const cleanMessage = ({ commit }) => {
  commit(types.CLEAN_MESSAGE);
};
