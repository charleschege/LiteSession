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

    pub fn add_acl(&mut self, resourse: &str) -> &mut Self {
        self.acl.push(resourse.into());

        self
    }

    pub fn remove_acl(&mut self, resource: &str) -> Option<&mut Self> {
        match self.acl.binary_search(&resource.into()) {
            Ok(index) => {
                self.acl.remove(index);
                Some(self)
            }
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
        acl_list.push_str(&format!("{:?}", initial));
        self.acl.iter().skip(1).for_each(|item| {
            acl_list.push(self.acl_separator());
            acl_list.push_str(&format!("{:?}", item))
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
