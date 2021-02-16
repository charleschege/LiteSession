use crate::{LiteSessionError, Role};

#[derive(Debug)]
pub struct LiteSessionData {
    username: String,
    role: Role,
    tag: Option<String>,
    acl: Vec<String>, //FIXME Make `acl` an enum of well known ACL fields
}

impl Default for LiteSessionData {
    fn default() -> Self {
        Self {
            username: String::default(),
            role: Role::default(),
            tag: Option::default(),
            acl: Vec::default(),
        }
    }
}

impl core::cmp::PartialEq for LiteSessionData {
    fn eq(&self, other: &Self) -> bool {
        if self.username == other.username
            && self.role == other.role
            && self.tag == other.tag
            && self.acl == other.acl
        {
            true
        } else {
            false
        }
    }
}

impl core::clone::Clone for LiteSessionData {
    //FIXME use cfg to enable only for tests
    fn clone(&self) -> Self {
        Self {
            username: self.username.clone(),
            role: self.role.clone(),
            tag: self.tag.clone(),
            acl: self.acl.clone(),
        }
    }
}

impl LiteSessionData {
    pub fn username(&mut self, value: &str) -> &mut Self {
        self.username = value.into();

        self
    }

    pub fn role(&mut self, role: Role) -> &mut Self {
        self.role = role;

        self
    }

    pub fn tag(&mut self, tag: &str) -> &mut Self {
        self.tag = Some(tag.into());

        self
    }

    pub fn add_acl(&mut self, resource: &str) -> &mut Self {
        self.acl.push(resource.into());
        self.acl.sort();

        self
    }

    pub fn remove_acl(&mut self, resource: &str) -> Option<String> {
        match self.acl.binary_search(&resource.to_owned()) {
            Ok(index) => Some(self.acl.remove(index)),
            Err(_) => None,
        }
    }

    pub fn build(&self) -> String {
        let mut acl_token = String::default();
        let mut acl_list = String::default();

        acl_token.push_str(&self.username);
        acl_token.push(self.ls_separator());
        acl_token.push_str(&Role::to_string(&self.role));
        acl_token.push(self.ls_separator());

        match &self.tag {
            None => acl_token.push_str("None"),
            Some(tag) => acl_token.push_str(&tag),
        }

        let initial = &self.acl[0];
        acl_list.push_str(&initial);
        self.acl.iter().skip(1).for_each(|item| {
            acl_list.push(self.acl_separator());
            acl_list.push_str(&item)
        });
        acl_token.push(self.ls_separator());
        acl_token.push_str(&acl_list);

        acl_token
    }

    pub fn destructure(mut self, data: &str) -> Result<Self, LiteSessionError> {
        let first_split: Vec<&str> = data.split(self.ls_separator()).collect();
        if first_split.len() != 4_usize {
            return Err(LiteSessionError::DataFieldsLengthError);
        }

        self.username = first_split[0].into();
        self.role = Role::from_str(first_split[1]);
        self.tag = match first_split[2] {
            "None" => None,
            _ => Some(first_split[2].into()),
        };

        let mut acl_list: Vec<String> = Vec::new();
        first_split[3]
            .split(self.acl_separator())
            .for_each(|acl| acl_list.push(acl.into()));
        self.acl = acl_list;

        Ok(self)
    }

    fn ls_separator(&self) -> char {
        '⥂'
    }

    fn acl_separator(&self) -> char {
        '⇅'
    }
}

#[cfg(test)]
mod data_tests {
    use super::{LiteSessionData, Role};

    #[test]
    fn data_tests() -> Result<(), crate::LiteSessionError> {
        let mut data = LiteSessionData::default();

        data.username("foo_user");
        assert_eq!(data.username, "foo_user");

        data.role(Role::SuperUser);
        assert_eq!(data.role, Role::SuperUser);

        data.tag("Foo-Tag");
        assert_eq!(data.tag, Some("Foo-Tag".into()));

        data.add_acl("Network-TCP");
        assert_eq!(data.acl, vec!["Network-TCP"]);

        data.add_acl("Network-UDP");
        let mut data_compare1 = vec!["Network-TCP", "Network-UDP"];
        data_compare1.sort();
        assert_eq!(data.acl, data_compare1);

        data.add_acl("Network-FTP");
        let mut data_compare2 = vec!["Network-TCP", "Network-UDP", "Network-FTP"];
        data_compare2.sort();
        assert_eq!(data.acl, data_compare2);

        assert_eq!(
            data.remove_acl("Network-FTP"),
            Some("Network-FTP".to_owned())
        );
        //assert_eq!(data.acl, vec!["Network-TCP", "Network-UDP"]);

        let prepared_data = data.build();
        assert_eq!(
            prepared_data,
            "foo_user⥂SuperUser⥂Foo-Tag⥂Network-TCP⇅Network-UDP".to_owned()
        );

        let destructured = LiteSessionData::default();
        let token_data = destructured.destructure(&prepared_data)?;

        assert_eq!(token_data.username, data.username);
        assert_eq!(token_data.role, data.role);
        assert_eq!(token_data.tag, data.tag);
        assert_eq!(token_data.acl, data.acl);

        Ok(())
    }
}
