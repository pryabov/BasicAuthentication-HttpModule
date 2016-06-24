using System.Configuration;

namespace WebBasicAuthentication.Configuration
{
	[ConfigurationCollection(typeof(RestrictionElement), CollectionType = ConfigurationElementCollectionType.BasicMap)]
	public class RestrictionElementCollection : ConfigurationElementCollection
	{
		public RestrictionElement this[int index]
		{
			get
			{
				return (RestrictionElement)BaseGet(index);
			}
			set
			{
				if (BaseGet(index) != null)
				{
					BaseRemoveAt(index);
				}
				BaseAdd(index, value);
			}
		}

		protected override ConfigurationElement CreateNewElement()
		{
			return new RestrictionElement();
		}

		protected override object GetElementKey(ConfigurationElement element)
		{
			return ((RestrictionElement)element).ToString();
		}
	}
}