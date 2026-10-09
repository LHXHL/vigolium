// An axios instance with a baseURL. Only the resolved URLs are real
// endpoints; the bare base and the un-prefixed paths are noise from the same
// call sites.
import axios from "axios";

const api = axios.create({ baseURL: "/api/v3" });

export function listThings() {
  return api.get("/things");
}

export function createThing(payload) {
  return api.post("/things", payload);
}

export function deleteThing(id) {
  return api.delete(`/things/${id}`);
}

axios.get("/api/v3/standalone");
