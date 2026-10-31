# checks.cogbox-vm phase LA: an option type error. The composition does not
# evaluate, so the apply is rejected (eval_error) before the guest is touched.
{ ... }: {
	environment.etc."la-bad".text = 5;
}
