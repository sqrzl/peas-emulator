/* @refresh reload */
import { render } from "solid-js/web";
import { Router, Route } from "@solidjs/router";
import { Buckets } from "./pages/buckets";
import { BucketContents } from "./pages/bucket-contents";
import { ThemeProvider } from "./utils/theme";
import "./index.css";

function App() {
  return (
    <ThemeProvider>
      <Router>
        <Route path="/" component={Buckets} />
        <Route path="/buckets" component={Buckets} />
        <Route path="/buckets/:bucket-name" component={BucketContents} />
        <Route path="/buckets/:bucket-name/*" component={BucketContents} />
      </Router>
    </ThemeProvider>
  );
}

const root = document.getElementById("root");

render(() => <App />, root!);
