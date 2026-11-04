import { Link } from "react-router-dom";
import { Button, EmptyState } from "../components/ui";

export function NotFound() {
  return <EmptyState title="Page not found" action={<Link to="/app"><Button variant="primary">Go to the workspace</Button></Link>}>That address does not exist in CyberRecon.</EmptyState>;
}
