import { redirect } from "next/navigation";
import { verifySession } from "./sessions";

export default async function HomePageToRedirect() {
  const { isLoggedIn } = await verifySession();
  if (!isLoggedIn) {
    redirect("/login");
  }
  redirect("/redirect");
}
