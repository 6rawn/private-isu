import { SharedArray } from "k6/data";

// vus(Virtual Users)間で共有されるReadonlyなArray
// それぞれのvusからSharedArrayに書き込まれたものは反映されない。

const accounts = new SharedArray("accounts", function() {
	return JSON.parse(open("./accounts.json"))
})

export function getAccount() {
	return accounts[Math.floor(Math.random() * accounts.length)]
}