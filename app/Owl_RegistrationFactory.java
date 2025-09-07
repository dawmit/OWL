package org.example;

interface Owl_RegistrationFactory
{
	Owl_ClientRegistration forClient();
	Owl_ServerRegistration forServer();
}
class Owl_RegistrationFactory implements Owl_RegistrationFactory
{
	public Owl_ClientRegistration forClient()
	{
		return new Owl_Registration();
	}

	public Owl_ServerRegistration forServer()
	{
		return new Owl_Registration();
	}
}