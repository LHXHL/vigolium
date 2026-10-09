// GraphQL operations, WebSocket and EventSource.
const GET_VIEWER = gql`
  query Viewer($first: Int!) {
    viewer { id name friends(first: $first) { id } }
  }
`;

fetch("/graphql", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ query: "query Ping { ping }", operationName: "Ping" }),
});

const socket = new WebSocket("wss://realtime.example.test/socket", ["v1.chat"]);
socket.send(JSON.stringify({ type: "subscribe", channel: "updates" }));

const events = new EventSource("/api/v1/stream", { withCredentials: true });
events.addEventListener("price", () => {});
