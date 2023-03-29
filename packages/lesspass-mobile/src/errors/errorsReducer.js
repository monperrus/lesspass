const initialState = {};

export default function (state = initialState, action) {
  switch (action.type) {
    case "ADD_ERROR":
      return {
        ...state,
        [action.error.id]: {
          ...action.error,
        },
      };
    case "DELETE_ERROR":
      delete state[action.error.id];
      return { ...state };
    case "LOG_IN":
    case "CLEAN_ERRORS":
      return { ...initialState };
    default:
      return state;
  }
}
